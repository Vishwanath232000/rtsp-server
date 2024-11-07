package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aler9/gortsplib"
	"github.com/aler9/gortsplib/pkg/base"
	"github.com/aler9/gortsplib/pkg/headers"
	"github.com/aler9/gortsplib/pkg/liberrors"

	"github.com/bhaney/rtsp-simple-server/internal/conf"
	"github.com/bhaney/rtsp-simple-server/internal/externalcmd"
	"github.com/bhaney/rtsp-simple-server/internal/logger"
	
)







type rtspServerAPIConnsListItem struct {
	Created       time.Time `json:"created"`
	RemoteAddr    string    `json:"remoteAddr"`
	BytesReceived uint64    `json:"bytesReceived"`
	BytesSent     uint64    `json:"bytesSent"`
}

type rtspServerAPIConnsListData struct {
	Items map[string]rtspServerAPIConnsListItem `json:"items"`
}

type rtspServerAPIConnsListRes struct {
	data *rtspServerAPIConnsListData
	err  error
}

type rtspServerAPISessionsListItem struct {
	Created       time.Time `json:"created"`
	RemoteAddr    string    `json:"remoteAddr"`
	State         string    `json:"state"`
	BytesReceived uint64    `json:"bytesReceived"`
	BytesSent     uint64    `json:"bytesSent"`
}

type rtspServerAPISessionsListData struct {
	Items map[string]rtspServerAPISessionsListItem `json:"items"`
}

type rtspServerAPISessionsListRes struct {
	data *rtspServerAPISessionsListData
	err  error
}

type rtspServerAPISessionsKickRes struct {
	err error
}

type rtspServerParent interface {
	Log(logger.Level, string, ...interface{})
}

func printAddresses(srv *gortsplib.Server) string {
	var ret []string

	ret = append(ret, fmt.Sprintf("%s (TCP)", srv.RTSPAddress))

	if srv.UDPRTPAddress != "" {
		ret = append(ret, fmt.Sprintf("%s (UDP/RTP)", srv.UDPRTPAddress))
	}

	if srv.UDPRTCPAddress != "" {
		ret = append(ret, fmt.Sprintf("%s (UDP/RTCP)", srv.UDPRTCPAddress))
	}

	return strings.Join(ret, ", ")
}

type rtspServer struct {
	externalAuthenticationURL string
	authMethods               []headers.AuthMethod
	readTimeout               conf.StringDuration
	isTLS                     bool
	rtspAddress               string
	protocols                 map[conf.Protocol]struct{}
	runOnConnect              string
	runOnConnectRestart       bool
	externalCmdPool           *externalcmd.Pool
	metrics                   *metrics
	pathManager               *pathManager
	parent                    rtspServerParent

	ctx       context.Context
	ctxCancel func()
	wg        sync.WaitGroup
	srv       *gortsplib.Server
	mutex     sync.RWMutex
	conns     map[*gortsplib.ServerConn]*rtspConn
	sessions  map[*gortsplib.ServerSession]*rtspSession
}

func newRTSPServer(
	parentCtx context.Context,
	externalAuthenticationURL string,
	address string,
	authMethods []headers.AuthMethod,
	readTimeout conf.StringDuration,
	writeTimeout conf.StringDuration,
	readBufferCount int,
	useUDP bool,
	useMulticast bool,
	rtpAddress string,
	rtcpAddress string,
	multicastIPRange string,
	multicastRTPPort int,
	multicastRTCPPort int,
	isTLS bool,
	serverCert string,
	serverKey string,
	rtspAddress string,
	protocols map[conf.Protocol]struct{},
	runOnConnect string,
	runOnConnectRestart bool,
	externalCmdPool *externalcmd.Pool,
	metrics *metrics,
	pathManager *pathManager,
	parent rtspServerParent,
) (*rtspServer, error) {
	
	ctx, ctxCancel := context.WithCancel(parentCtx)

	s := &rtspServer{
		externalAuthenticationURL: externalAuthenticationURL,
		authMethods:               authMethods,
		readTimeout:               readTimeout,
		isTLS:                     isTLS,
		rtspAddress:               rtspAddress,
		protocols:                 protocols,
		externalCmdPool:           externalCmdPool,
		metrics:                   metrics,
		pathManager:               pathManager,
		parent:                    parent,
		ctx:                       ctx,
		ctxCancel:                 ctxCancel,
		conns:                     make(map[*gortsplib.ServerConn]*rtspConn),
		sessions:                  make(map[*gortsplib.ServerSession]*rtspSession),
	}

	s.log(logger.Debug,"newRTSPServer: Begin")
	s.srv = &gortsplib.Server{
		Handler:          s,
		ReadTimeout:      time.Duration(readTimeout),
		WriteTimeout:     time.Duration(writeTimeout),
		ReadBufferCount:  readBufferCount,
		WriteBufferCount: readBufferCount,
		RTSPAddress:      address,
	}

	if useUDP {
		s.srv.UDPRTPAddress = rtpAddress
		s.srv.UDPRTCPAddress = rtcpAddress
	}

	if useMulticast {
		s.srv.MulticastIPRange = multicastIPRange
		s.srv.MulticastRTPPort = multicastRTPPort
		s.srv.MulticastRTCPPort = multicastRTCPPort
	}

	if isTLS {
		cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
		if err != nil {
			s.log(logger.Debug,"newRTSPServer: End-1")
			return nil, err
		}

		s.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	err := s.srv.Start()
	if err != nil {
		s.log(logger.Debug,"newRTSPServer: End-2")
		return nil, err
	}

	s.log(logger.Info, "listener opened on %s", printAddresses(s.srv))

	if s.metrics != nil {
		if !isTLS {
			s.metrics.rtspServerSet(s)
		} else {
			s.metrics.rtspsServerSet(s)
		}
	}

	s.wg.Add(1)
	go s.run()
	s.log(logger.Debug,"newRTSPServer: End-99")

	return s, nil
}

func (s *rtspServer) log(level logger.Level, format string, args ...interface{}) {
	label := func() string {
		if s.isTLS {
			return "RTSPS"
		}
		
		return "RTSP"
	}()
	s.parent.Log(level, "[%s] "+format, append([]interface{}{label}, args...)...)
}

func (s *rtspServer) close() {
	s.log(logger.Debug,"close: Begin")
	s.log(logger.Info, "listener is closing")
	s.ctxCancel()
	s.wg.Wait()
	s.log(logger.Debug,"close: End-99")
	
}

func (s *rtspServer) run() {
	s.log(logger.Debug,"run: Begin")
	defer s.wg.Done()

	serverErr := make(chan error)
	go func() {
		serverErr <- s.srv.Wait()
	}()

outer:
	select {
	case err := <-serverErr:
		s.log(logger.Error, "%s", err)
		break outer

	case <-s.ctx.Done():
		s.srv.Close()
		<-serverErr
		break outer
	}

	s.ctxCancel()

	if s.metrics != nil {
		if !s.isTLS {
			s.metrics.rtspServerSet(nil)
		} else {
			s.metrics.rtspsServerSet(nil)
		}
	}
	s.log(logger.Debug,"run: End-99")
}

// OnConnOpen implements gortsplib.ServerHandlerOnConnOpen.
func (s *rtspServer) OnConnOpen(ctx *gortsplib.ServerHandlerOnConnOpenCtx) {
	s.log(logger.Debug,"OnConnOpen: Begin")
	c := newRTSPConn(
		s.externalAuthenticationURL,
		s.rtspAddress,
		s.authMethods,
		s.readTimeout,
		s.runOnConnect,
		s.runOnConnectRestart,
		s.externalCmdPool,
		s.pathManager,
		ctx.Conn,
		s)
	s.mutex.Lock()
	s.conns[ctx.Conn] = c
	s.mutex.Unlock()

	ctx.Conn.SetUserData(c)
	s.log(logger.Debug,"OnConnOpen: End-99")

}

// OnConnClose implements gortsplib.ServerHandlerOnConnClose.
func (s *rtspServer) OnConnClose(ctx *gortsplib.ServerHandlerOnConnCloseCtx) {
	s.log(logger.Debug,"OnConnClose: Begin")
	s.mutex.Lock()
	c := s.conns[ctx.Conn]
	delete(s.conns, ctx.Conn)
	s.mutex.Unlock()
	c.onClose(ctx.Error)
	s.log(logger.Debug,"OnConnClose: End-99")
	
}

// OnRequest implements gortsplib.ServerHandlerOnRequest.
func (s *rtspServer) OnRequest(sc *gortsplib.ServerConn, req *base.Request) {
	s.log(logger.Debug,"OnRequest: Begin")
	c := sc.UserData().(*rtspConn)
	c.onRequest(req)
	s.log(logger.Debug,"OnRequest: End-99")
}

// OnResponse implements gortsplib.ServerHandlerOnResponse.
func (s *rtspServer) OnResponse(sc *gortsplib.ServerConn, res *base.Response) {
	s.log(logger.Debug,"OnResponse: Begin")
	c := sc.UserData().(*rtspConn)
	c.OnResponse(res)
	s.log(logger.Debug,"OnResponse: End-99")
}

// OnSessionOpen implements gortsplib.ServerHandlerOnSessionOpen.
func (s *rtspServer) OnSessionOpen(ctx *gortsplib.ServerHandlerOnSessionOpenCtx) {
	s.log(logger.Debug,"OnSessionOpen: Begin")
	se := newRTSPSession(
		s.isTLS,
		s.protocols,
		ctx.Session,
		ctx.Conn,
		s.externalCmdPool,
		s.pathManager,
		s)
	s.mutex.Lock()
	s.sessions[ctx.Session] = se
	s.mutex.Unlock()
	ctx.Session.SetUserData(se)
	s.log(logger.Debug,"OnSessionOpen: End-99")
}

// OnSessionClose implements gortsplib.ServerHandlerOnSessionClose.
func (s *rtspServer) OnSessionClose(ctx *gortsplib.ServerHandlerOnSessionCloseCtx) {
	s.log(logger.Debug,"OnSessionClose: Begin")
	s.mutex.Lock()
	se := s.sessions[ctx.Session]
	delete(s.sessions, ctx.Session)
	s.mutex.Unlock()

	if se != nil {
		se.onClose(ctx.Error)
	}
	s.log(logger.Debug,"OnSessionClose: End-99")
}

// OnDescribe implements gortsplib.ServerHandlerOnDescribe.
func (s *rtspServer) OnDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	s.log(logger.Debug,"OnDescribe: Begin")
	c := ctx.Conn.UserData().(*rtspConn)
	s.log(logger.Debug,"OnDescribe: End-99")
	return c.onDescribe(ctx)
}

// OnAnnounce implements gortsplib.ServerHandlerOnAnnounce.
func (s *rtspServer) OnAnnounce(ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	s.log(logger.Debug,"OnAnnounce: Begin")
	c := ctx.Conn.UserData().(*rtspConn)
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug,"OnAnnounce: End-99")
	return se.onAnnounce(c, ctx)
}

// OnSetup implements gortsplib.ServerHandlerOnSetup.
func (s *rtspServer) OnSetup(ctx *gortsplib.ServerHandlerOnSetupCtx) (*base.Response, *gortsplib.ServerStream, error) {
	s.log(logger.Debug,"OnSetup: Begin")
	c := ctx.Conn.UserData().(*rtspConn)
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug,"OnSetup: End-99")
	return se.onSetup(c, ctx)
}

// OnPlay implements gortsplib.ServerHandlerOnPlay.
func (s *rtspServer) OnPlay(ctx *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	s.log(logger.Debug,"OnPlay: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug,"OnPlay: End-99")
	return se.onPlay(ctx)
}

// OnRecord implements gortsplib.ServerHandlerOnRecord.
func (s *rtspServer) OnRecord(ctx *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	s.log(logger.Debug,"OnRecord: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug,"OnRecord: Begin")
	return se.onRecord(ctx)
}

// OnPause implements gortsplib.ServerHandlerOnPause.
func (s *rtspServer) OnPause(ctx *gortsplib.ServerHandlerOnPauseCtx) (*base.Response, error) {
	s.log(logger.Debug,"OnPause: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug,"OnPause: End-99")
	return se.onPause(ctx)
}

// OnPacketRTP implements gortsplib.ServerHandlerOnPacketRTP.
func (s *rtspServer) OnPacketRTP(ctx *gortsplib.ServerHandlerOnPacketRTPCtx) {
	s.log(logger.Debug,"OnPacketRTP: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug,"OnPacketRTP: End-99")
	se.onPacketRTP(ctx)
}

// OnDecodeError implements gortsplib.ServerHandlerOnOnDecodeError.
func (s *rtspServer) OnDecodeError(ctx *gortsplib.ServerHandlerOnDecodeErrorCtx) {
	s.log(logger.Debug,"OnDecodeError: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	se.onDecodeError(ctx)
	s.log(logger.Debug,"OnDecodeError: End-99")
	
}

// apiConnsList is called by api and metrics.
func (s *rtspServer) apiConnsList() rtspServerAPIConnsListRes {
	s.log(logger.Debug,"apiConnsList: Begin")
	select {
	case <-s.ctx.Done():
		return rtspServerAPIConnsListRes{err: fmt.Errorf("terminated")}
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	data := &rtspServerAPIConnsListData{
		Items: make(map[string]rtspServerAPIConnsListItem),
	}

	for _, c := range s.conns {
		data.Items[c.uuid.String()] = rtspServerAPIConnsListItem{
			Created:       c.created,
			RemoteAddr:    c.remoteAddr().String(),
			BytesReceived: c.conn.BytesReceived(),
			BytesSent:     c.conn.BytesSent(),
		}
	}

	s.log(logger.Debug,"apiConnsList: End-99")
	return rtspServerAPIConnsListRes{data: data}
}

// apiSessionsList is called by api and metrics.
func (s *rtspServer) apiSessionsList() rtspServerAPISessionsListRes {
	s.log(logger.Debug,"apiSessionsList: Begin")
	select {
	case <-s.ctx.Done():
		s.log(logger.Debug,"apiSessionsList: End-1")
		return rtspServerAPISessionsListRes{err: fmt.Errorf("terminated")}
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	data := &rtspServerAPISessionsListData{
		Items: make(map[string]rtspServerAPISessionsListItem),
	}

	for _, s := range s.sessions {
		data.Items[s.uuid.String()] = rtspServerAPISessionsListItem{
			Created:    s.created,
			RemoteAddr: s.remoteAddr().String(),
			State: func() string {
				switch s.safeState() {
				case gortsplib.ServerSessionStatePrePlay,
					gortsplib.ServerSessionStatePlay:
					s.log(logger.Debug,"apiSessionsList: End-2")
					return "read"

				case gortsplib.ServerSessionStatePreRecord,
					gortsplib.ServerSessionStateRecord:
					s.log(logger.Debug,"apiSessionsList: End-3")
					return "publish"
				}
				s.log(logger.Debug,"apiSessionsList: End-4")
				return "idle"
			}(),
			BytesReceived: s.session.BytesReceived(),
			BytesSent:     s.session.BytesSent(),
		}
	}
	s.log(logger.Debug,"apiSessionsList: End-99")

	return rtspServerAPISessionsListRes{data: data}
}

// apiSessionsKick is called by api.
func (s *rtspServer) apiSessionsKick(id string) rtspServerAPISessionsKickRes {
	s.log(logger.Debug,"apiSessionsKick: Begin")
	select {
	case <-s.ctx.Done():
		s.log(logger.Debug,"apiSessionsKick: End-1")
		return rtspServerAPISessionsKickRes{err: fmt.Errorf("terminated")}
	default:
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for key, se := range s.sessions {
		if se.uuid.String() == id {
			se.close()
			delete(s.sessions, key)
			se.onClose(liberrors.ErrServerTerminated{})
			s.log(logger.Debug,"apiSessionsKick: End-2")
			return rtspServerAPISessionsKickRes{}
		}
	}
	s.log(logger.Debug,"apiSessionsKick: End-99")

	return rtspServerAPISessionsKickRes{err: fmt.Errorf("not found")}
}
