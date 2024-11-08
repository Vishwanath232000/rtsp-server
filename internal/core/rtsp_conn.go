package core

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/aler9/gortsplib"
	"github.com/aler9/gortsplib/pkg/auth"
	"github.com/aler9/gortsplib/pkg/base"
	"github.com/aler9/gortsplib/pkg/headers"
	"github.com/google/uuid"

	"github.com/bhaney/rtsp-simple-server/internal/conf"
	"github.com/bhaney/rtsp-simple-server/internal/externalcmd"
	"github.com/bhaney/rtsp-simple-server/internal/logger"
)

const (
	rtspConnPauseAfterAuthError = 2 * time.Second
)

type rtspConnParent interface {
	log(logger.Level, string, ...interface{})
}

type rtspConn struct {
	externalAuthenticationURL string
	rtspAddress               string
	authMethods               []headers.AuthMethod
	readTimeout               conf.StringDuration
	runOnConnect              string
	runOnConnectRestart       bool
	externalCmdPool           *externalcmd.Pool
	pathManager               *pathManager
	conn                      *gortsplib.ServerConn
	parent                    rtspConnParent

	uuid          uuid.UUID
	created       time.Time
	onConnectCmd  *externalcmd.Cmd
	authUser      string
	authPass      string
	authValidator *auth.Validator
	authFailures  int
}

func newRTSPConn(
	externalAuthenticationURL string,
	rtspAddress string,
	authMethods []headers.AuthMethod,
	readTimeout conf.StringDuration,
	runOnConnect string,
	runOnConnectRestart bool,
	externalCmdPool *externalcmd.Pool,
	pathManager *pathManager,
	conn *gortsplib.ServerConn,
	parent rtspConnParent,
) *rtspConn {

	c := &rtspConn{
		externalAuthenticationURL: externalAuthenticationURL,
		rtspAddress:               rtspAddress,
		authMethods:               authMethods,
		readTimeout:               readTimeout,
		runOnConnect:              runOnConnect,
		runOnConnectRestart:       runOnConnectRestart,
		externalCmdPool:           externalCmdPool,
		pathManager:               pathManager,
		conn:                      conn,
		parent:                    parent,
		uuid:                      uuid.New(),
		created:                   time.Now(),
	}
	c.log(logger.Debug, "rtsp_conn.go> newRTSPConn: Begin: %s", c.uuid)

	// c.log(logger.Info, "opened rtspAdress:[%s]| conn:[%s] | parent[%s]",rtspAddress,conn,parent)

	if c.runOnConnect != "" {
		c.log(logger.Info, "runOnConnect command started")
		_, port, _ := net.SplitHostPort(c.rtspAddress)
		c.onConnectCmd = externalcmd.NewCmd(
			c.externalCmdPool,
			c.runOnConnect,
			c.runOnConnectRestart,
			externalcmd.Environment{
				"RTSP_PATH": "",
				"RTSP_PORT": port,
			},
			func(co int) {
				c.log(logger.Info, "runOnInit command exited with code %d", co)
			})
	}

	c.log(logger.Debug, "rtsp_conn.go> newRTSPConn: End-99: %s", c.uuid)
	return c
}

func (c *rtspConn) log(level logger.Level, format string, args ...interface{}) {

	c.parent.log(level, "[conn %v] "+format, append([]interface{}{c.conn.NetConn().RemoteAddr()}, args...)...)
}

// Conn returns the RTSP connection.
func (c *rtspConn) Conn() *gortsplib.ServerConn {
	return c.conn
}

func (c *rtspConn) remoteAddr() net.Addr {
	return c.conn.NetConn().RemoteAddr()
}

func (c *rtspConn) ip() net.IP {
	return c.conn.NetConn().RemoteAddr().(*net.TCPAddr).IP
}

func (c *rtspConn) authenticate(
	pathName string,
	pathIPs []fmt.Stringer,
	pathUser conf.Credential,
	pathPass conf.Credential,
	isPublishing bool,
	req *base.Request,
	query string,
) error {
	c.log(logger.Debug, "rtsp_conn.go> authenticate: Begin")
	if c.externalAuthenticationURL != "" {
		username := ""
		password := ""

		var auth headers.Authorization
		err := auth.Unmarshal(req.Header["Authorization"])
		if err == nil && auth.Method == headers.AuthBasic {
			username = auth.BasicUser
			password = auth.BasicPass
		}

		err = externalAuth(
			c.externalAuthenticationURL,
			c.ip().String(),
			username,
			password,
			pathName,
			isPublishing,
			query)
		if err != nil {
			c.authFailures++

			// VLC with login prompt sends 4 requests:
			// 1) without credentials
			// 2) with password but without username
			// 3) without credentials
			// 4) with password and username
			// therefore we must allow up to 3 failures
			if c.authFailures > 3 {
				return pathErrAuthCritical{
					message: "unauthorized: " + err.Error(),
					response: &base.Response{
						StatusCode: base.StatusUnauthorized,
					},
				}
			}

			v := "IPCAM"
			return pathErrAuthNotCritical{
				message: "unauthorized: " + err.Error(),
				response: &base.Response{
					StatusCode: base.StatusUnauthorized,
					Header: base.Header{
						"WWW-Authenticate": headers.Authenticate{
							Method: headers.AuthBasic,
							Realm:  &v,
						}.Marshal(),
					},
				},
			}
		}
	}

	if pathIPs != nil {
		ip := c.ip()
		if !ipEqualOrInRange(ip, pathIPs) {
			c.log(logger.Debug, "rtsp_conn.go> authenticate: End-1")
			return pathErrAuthCritical{
				message: fmt.Sprintf("IP '%s' not allowed", ip),
				response: &base.Response{
					StatusCode: base.StatusUnauthorized,
				},
			}
		}
	}

	if pathUser != "" {
		// reset authValidator every time the credentials change
		if c.authValidator == nil || c.authUser != string(pathUser) || c.authPass != string(pathPass) {
			c.authUser = string(pathUser)
			c.authPass = string(pathPass)
			c.authValidator = auth.NewValidator(string(pathUser), string(pathPass), c.authMethods)
		}

		err := c.authValidator.ValidateRequest(req)
		if err != nil {
			c.authFailures++

			// VLC with login prompt sends 4 requests:
			// 1) without credentials
			// 2) with password but without username
			// 3) without credentials
			// 4) with password and username
			// therefore we must allow up to 3 failures
			if c.authFailures > 3 {
				return pathErrAuthCritical{
					message: "unauthorized: " + err.Error(),
					response: &base.Response{
						StatusCode: base.StatusUnauthorized,
					},
				}
			}
			c.log(logger.Debug, "rtsp_conn.go> authenticate: End-2")

			return pathErrAuthNotCritical{
				response: &base.Response{
					StatusCode: base.StatusUnauthorized,
					Header: base.Header{
						"WWW-Authenticate": c.authValidator.Header(),
					},
				},
			}
		}

		// login successful, reset authFailures
		c.authFailures = 0
	}
	c.log(logger.Debug, "rtsp_conn.go> authenticate: End-99")
	return nil
}

// onClose is called by rtspServer.
func (c *rtspConn) onClose(err error) {
	c.log(logger.Debug, "rtsp_conn.go> onClose: Begin")
	// c.log(logger.Info, "closed (%v)", err)

	if c.onConnectCmd != nil {
		c.onConnectCmd.Close()
		c.log(logger.Info, "runOnConnect command stopped")
	}
	c.log(logger.Debug, "rtsp_conn.go> onClose: End-99")
}

// onRequest is called by rtspServer.
func (c *rtspConn) onRequest(req *base.Request) {
	c.log(logger.Debug, "rtsp_conn.go> onRequest: Begin")
	c.log(logger.Debug, "rtsp_conn.go> onRequest: End")
}

// OnResponse is called by rtspServer.
func (c *rtspConn) OnResponse(res *base.Response) {
	c.log(logger.Debug, "rtsp_conn.go> OnResponse: Begin")
	c.log(logger.Debug, "rtsp_conn.go> OnResponse: End")
}

// onDescribe is called by rtspServer.
func (c *rtspConn) onDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	c.log(logger.Debug, "rtsp_conn.go> onDescribe: Begin")
	res := c.pathManager.describe(pathDescribeReq{
		pathName: ctx.Path,
		url:      ctx.Request.URL,
		authenticate: func(
			pathIPs []fmt.Stringer,
			pathUser conf.Credential,
			pathPass conf.Credential,
		) error {
			c.log(logger.Debug, "onDescribe: End-1")
			return c.authenticate(ctx.Path, pathIPs, pathUser, pathPass, false, ctx.Request, ctx.Query)
		},
	})

	if res.err != nil {
		switch terr := res.err.(type) {
		case pathErrAuthNotCritical:
			c.log(logger.Debug, "non-critical authentication error: %s", terr.message)
			c.log(logger.Debug, "rtsp_conn.go> onDescribe: End-2")
			return terr.response, nil, nil

		case pathErrAuthCritical:
			// wait some seconds to stop brute force attacks
			<-time.After(rtspConnPauseAfterAuthError)
			c.log(logger.Debug, "rtsp_conn.go> onDescribe: End-3")

			return terr.response, nil, errors.New(terr.message)

		case pathErrNoOnePublishing:
			c.log(logger.Debug, "rtsp_conn.go> onDescribe: End-4")
			return &base.Response{
				StatusCode: base.StatusNotFound,
			}, nil, res.err

		default:
			c.log(logger.Debug, "rtsp_conn.go> onDescribe: End-5")
			return &base.Response{
				StatusCode: base.StatusBadRequest,
			}, nil, res.err
		}
	}

	if res.redirect != "" {
		c.log(logger.Debug, "rtsp_conn.go> onDescribe: End-6")
		return &base.Response{
			StatusCode: base.StatusMovedPermanently,
			Header: base.Header{
				"Location": base.HeaderValue{res.redirect},
			},
		}, nil, nil
	}

	c.log(logger.Debug, "rtsp_conn.go> onDescribe: End-99")
	return &base.Response{
		StatusCode: base.StatusOK,
	}, res.stream.rtspStream, nil
}
