package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

	"io"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var my_version int = 8
var my_folder string = "rtsp-simple-server-main-001"

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
	fmt.Printf("rtsp_server.go> newRTSPServer: %s: Version: %d\n", my_folder, my_version)
	s.log(logger.Debug, "rtsp_server.go> newRTSPServer: %s [%d] Begin", my_folder, my_version)
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
			s.log(logger.Debug, "rtsp_server.go> newRTSPServer: End-1")
			return nil, err
		}

		s.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	err := s.srv.Start()
	if err != nil {
		s.log(logger.Debug, "rtsp_server.go> newRTSPServer: End-2")
		return nil, err
	}

	// s.log(logger.Info, "listener opened on %s", printAddresses(s.srv))

	if s.metrics != nil {
		if !isTLS {
			s.metrics.rtspServerSet(s)
		} else {
			s.metrics.rtspsServerSet(s)
		}
	}

	s.wg.Add(1)
	go s.run()
	s.log(logger.Debug, "rtsp_server.go> newRTSPServer: End-99")

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
	updateDynamoDBStopTime(server_instance_id)
	s.log(logger.Debug, "rtsp_server.go> close: Begin")
	s.log(logger.Info, "listener is closing")
	s.ctxCancel()
	s.wg.Wait()
	s.log(logger.Debug, "rtsp_server.go> close: End-99")

}

func (s *rtspServer) run() {
	s.log(logger.Debug, "rtsp_server.go> run: Begin")
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
	s.log(logger.Debug, "rtsp_server.go> run: End-99")
}

// OnConnOpen implements gortsplib.ServerHandlerOnConnOpen.
func (s *rtspServer) OnConnOpen(ctx *gortsplib.ServerHandlerOnConnOpenCtx) {
	s.log(logger.Debug, "rtsp_server.go> OnConnOpen: Begin")
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
	s.log(logger.Debug, "rtsp_server.go> OnConnOpen: End-99")

}

// OnConnClose implements gortsplib.ServerHandlerOnConnClose.
func (s *rtspServer) OnConnClose(ctx *gortsplib.ServerHandlerOnConnCloseCtx) {
	s.log(logger.Debug, "rtsp_server.go> OnConnClose: Begin")
	s.mutex.Lock()
	c := s.conns[ctx.Conn]
	delete(s.conns, ctx.Conn)
	s.mutex.Unlock()
	c.onClose(ctx.Error)
	s.log(logger.Debug, "rtsp_server.go> OnConnClose: %s [%d] End-99", my_folder, my_version)
	// s.log(logger.Debug, "rtsp_server.go> OnConnClose: End-99")

}

// OnRequest implements gortsplib.ServerHandlerOnRequest.
func (s *rtspServer) OnRequest(sc *gortsplib.ServerConn, req *base.Request) {
	s.log(logger.Debug, "rtsp_server.go> OnRequest: Begin")
	c := sc.UserData().(*rtspConn)
	c.onRequest(req)
	s.log(logger.Debug, "rtsp_server.go> OnRequest: End-99")

}

// OnResponse implements gortsplib.ServerHandlerOnResponse.
func (s *rtspServer) OnResponse(sc *gortsplib.ServerConn, res *base.Response) {
	s.log(logger.Debug, "rtsp_server.go> OnResponse: Begin")
	c := sc.UserData().(*rtspConn)
	c.OnResponse(res)
	s.log(logger.Debug, "rtsp_server.go> OnResponse: End-99")
}

// OnSessionOpen implements gortsplib.ServerHandlerOnSessionOpen.
func (s *rtspServer) OnSessionOpen(ctx *gortsplib.ServerHandlerOnSessionOpenCtx) {
	s.log(logger.Debug, "rtsp_server.go> OnSessionOpen: Begin")
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
	s.log(logger.Debug, "rtsp_server.go> OnSessionOpen: End-99")
}

// OnSessionClose implements gortsplib.ServerHandlerOnSessionClose.
func (s *rtspServer) OnSessionClose(ctx *gortsplib.ServerHandlerOnSessionCloseCtx) {
	s.log(logger.Debug, "rtsp_server.go> OnSessionClose: Begin")
	s.mutex.Lock()
	se := s.sessions[ctx.Session]
	delete(s.sessions, ctx.Session)
	s.mutex.Unlock()

	if se != nil {
		se.onClose(ctx.Error)
	}
	s.log(logger.Debug, "rtsp_server.go> OnSessionCloses: %s [%d] End-99", my_folder, my_version)
}

// OnDescribe implements gortsplib.ServerHandlerOnDescribe.
func (s *rtspServer) OnDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	s.log(logger.Debug, "rtsp_server.go> OnDescribe: Begin")
	c := ctx.Conn.UserData().(*rtspConn)
	s.log(logger.Debug, "rtsp_server.go> OnDescribe: End-99")
	return c.onDescribe(ctx)
}

// OnAnnounce implements gortsplib.ServerHandlerOnAnnounce.
func (s *rtspServer) OnAnnounce(ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	s.log(logger.Debug, "rtsp_server.go> OnAnnounce: Begin")
	c := ctx.Conn.UserData().(*rtspConn)
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug, "rtsp_server.go> OnAnnounce: End-99")
	return se.onAnnounce(c, ctx)
}

// OnSetup implements gortsplib.ServerHandlerOnSetup.
func (s *rtspServer) OnSetup(ctx *gortsplib.ServerHandlerOnSetupCtx) (*base.Response, *gortsplib.ServerStream, error) {
	s.log(logger.Debug, "rtsp_server.go> OnSetup: Begin")
	c := ctx.Conn.UserData().(*rtspConn)
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug, "rtsp_server.go> OnSetup: End-99")
	return se.onSetup(c, ctx)
}

// OnPlay implements gortsplib.ServerHandlerOnPlay.
func (s *rtspServer) OnPlay(ctx *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	s.log(logger.Debug, "rtsp_server.go> OnPlay: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug, "rtsp_server.go> OnPlay: End-99")
	return se.onPlay(ctx)
}

// OnRecord implements gortsplib.ServerHandlerOnRecord.
func (s *rtspServer) OnRecord(ctx *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	s.log(logger.Debug, "rtsp_server.go> OnRecord: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug, "rtsp_server.go> OnRecord: End-99")
	return se.onRecord(ctx)
}

// OnPause implements gortsplib.ServerHandlerOnPause.
func (s *rtspServer) OnPause(ctx *gortsplib.ServerHandlerOnPauseCtx) (*base.Response, error) {
	s.log(logger.Debug, "rtsp_server.go> OnPause: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	s.log(logger.Debug, "rtsp_server.go> OnPause: End-99")
	return se.onPause(ctx)
}

// OnPacketRTP implements gortsplib.ServerHandlerOnPacketRTP.
func (s *rtspServer) OnPacketRTP(ctx *gortsplib.ServerHandlerOnPacketRTPCtx) {
	// s.log(logger.Debug, "rtsp_server.go> OnPacketRTP: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	se.onPacketRTP(ctx)
	// s.log(logger.Debug, "rtsp_server.go> OnPacketRTP: End-99")
}

// OnDecodeError implements gortsplib.ServerHandlerOnOnDecodeError.
func (s *rtspServer) OnDecodeError(ctx *gortsplib.ServerHandlerOnDecodeErrorCtx) {
	s.log(logger.Debug, "rtsp_server.go> OnDecodeError: Begin")
	se := ctx.Session.UserData().(*rtspSession)
	se.onDecodeError(ctx)
	s.log(logger.Debug, "rtsp_server.go> OnDecodeError: End-99")

}

// apiConnsList is called by api and metrics.
func (s *rtspServer) apiConnsList() rtspServerAPIConnsListRes {
	s.log(logger.Debug, "rtsp_server.go> apiConnsList: Begin")
	select {
	case <-s.ctx.Done():
		s.log(logger.Debug, "rtsp_server.go> apiConnsList: End-1")
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

	s.log(logger.Debug, "rtsp_server.go> apiConnsList: End-99")
	return rtspServerAPIConnsListRes{data: data}
}

// apiSessionsList is called by api and metrics.
func (s *rtspServer) apiSessionsList() rtspServerAPISessionsListRes {
	s.log(logger.Debug, "rtsp_server.go> apiSessionsList: Begin")
	select {
	case <-s.ctx.Done():
		s.log(logger.Debug, "rtsp_server.go> apiSessionsList: End-1")
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
					s.log(logger.Debug, "apiSessionsList: End-2")
					return "read"

				case gortsplib.ServerSessionStatePreRecord,
					gortsplib.ServerSessionStateRecord:
					s.log(logger.Debug, "apiSessionsList: End-3")
					return "publish"
				}
				s.log(logger.Debug, "apiSessionsList: End-4")
				return "idle"
			}(),
			BytesReceived: s.session.BytesReceived(),
			BytesSent:     s.session.BytesSent(),
		}
	}
	s.log(logger.Debug, "rtsp_server.go> apiSessionsList: End-99")

	return rtspServerAPISessionsListRes{data: data}
}

// apiSessionsKick is called by api.
func (s *rtspServer) apiSessionsKick(id string) rtspServerAPISessionsKickRes {
	s.log(logger.Debug, "rtsp_server.go> apiSessionsKick: Begin")
	select {
	case <-s.ctx.Done():
		s.log(logger.Debug, "rtsp_server.go> apiSessionsKick: End-1")
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
			s.log(logger.Debug, "rtsp_server.go> apiSessionsKick: End-2")
			return rtspServerAPISessionsKickRes{}
		}
	}
	s.log(logger.Debug, "rtsp_server.go> apiSessionsKick: End-99")

	return rtspServerAPISessionsKickRes{err: fmt.Errorf("not found")}
}

var dynamoDBHostTableName string
var server_instance_id string
var server_operating_system = runtime.GOOS
var server_environment string
var server_public_ip string

type InstanceDetails struct {
	InstanceID string `json:"instance_id"`
	HostType   string `json:"host_type"`
	OS         string `json:"os"`
	PrivateIP  string `json:"private_ip"`
	PublicIP   string `json:"public_ip"`
	Region     string `json:"region"`
}

// init is called automatically when the package is loaded
func init() {
	dynamoDBHostTableName = os.Getenv("DYNAMODB_HOST_INFO_TABLE_NAME")
	if dynamoDBHostTableName == "" {
		log.Fatal("DYNAMODB_TABLE_NAME environment variable is not set")
		dynamoDBHostTableName = "sam-rtsp-server-hosts"
	}

	// Determine if running on Fargate or EC2
	go func() {
		var instanceDetails InstanceDetails
		var err error

		// Check if Fargate metadata URI is set to decide the environment
		if os.Getenv("ECS_CONTAINER_METADATA_URI_V4") != "" {

			// Running on Fargate
			instanceDetails, err = getFargateMetadata()
			if err != nil {
				log.Printf("Failed to get Fargate metadata: %v", err)
				return
			}
		} else {
			// Assume running on EC2
			instanceDetails, err = getInstanceMetadata()

			if err != nil {
				log.Printf("Failed to get EC2 instance metadata: %v", err)
				return
			}
		}

		// Log instance details and start the background update to DynamoDB
		log.Println("Instance details : ", instanceDetails)
		log.Println("Server : ", instanceDetails.HostType)
		updateDynamoDB(instanceDetails)
	}()
}

func getMetadataUsingToken() (map[string]string, error) {
	metadata := make(map[string]string)

	// Define all metadata URIs that you need to fetch
	urls := []string{
		"instance-id",
		"placement/availability-zone",
		"public-ipv4",
		"local-ipv4",
	}

	// Loop through each URL and fetch the metadata
	for _, url := range urls {
		fullURL := "http://169.254.169.254/latest/meta-data/" + url
		resp, err := http.Get(fullURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch metadata from %s: %v", fullURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch metadata: %v", resp.Status)
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read metadata response body: %v", err)
		}

		metadata[url] = string(data)
	}

	return metadata, nil
}

func getInstanceMetadata() (InstanceDetails, error) {
	instanceDetails := InstanceDetails{}
	metadata, err := getMetadataUsingToken()
	if err != nil {
		return instanceDetails, fmt.Errorf("failed to get instance metadata: %v", err)
	}

	// Populate the InstanceDetails struct with metadata
	instanceDetails.InstanceID = metadata["instance-id"]
	instanceDetails.Region = metadata["placement/availability-zone"]
	instanceDetails.PublicIP = metadata["public-ipv4"]
	instanceDetails.PrivateIP = metadata["local-ipv4"]
	server_instance_id = metadata["instance-id"]
	instanceDetails.HostType = "EC2"
	server_environment = "EC2"
	instanceDetails.OS = server_operating_system
	server_public_ip = getPublicIP()
	return instanceDetails, nil
}

func getFargateMetadata() (InstanceDetails, error) {
	var instanceDetails InstanceDetails

	// Get the metadata URI from the environment variable
	metadataUri := os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
	if metadataUri == "" {
		metadataUri = "http://169.254.170.2/v4"
	}

	// Append /task to get full task metadata
	taskEndpoint := metadataUri + "/task"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", taskEndpoint, nil)
	if err != nil {
		return instanceDetails, fmt.Errorf("error creating request for Fargate metadata: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return instanceDetails, fmt.Errorf("error retrieving Fargate metadata: %v", err)
	}
	defer resp.Body.Close()

	var metadata struct {
		TaskARN    string `json:"TaskARN"`
		Containers []struct {
			Networks []struct {
				NetworkMode       string   `json:"NetworkMode"`
				IPv4Addresses     []string `json:"IPv4Addresses"`
				PublicIPv4Address string   `json:"PublicIPv4Address"`
			} `json:"Networks"`
		} `json:"Containers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return instanceDetails, fmt.Errorf("error decoding Fargate metadata JSON: %v", err)
	}

	// Extract the Task ID and Region from the Task ARN
	arnParts := strings.Split(metadata.TaskARN, ":")
	if len(arnParts) > 3 {
		instanceDetails.Region = arnParts[3]
	} else {
		instanceDetails.Region = "unknown" // fallback if parsing fails
	}

	taskID := "task-id"
	taskIDParts := strings.Split(metadata.TaskARN, "/")
	if len(taskIDParts) > 1 {
		taskID = taskIDParts[len(taskIDParts)-1]
	}
	instanceDetails.InstanceID = taskID

	// Iterate over containers to find the network info
	for _, container := range metadata.Containers {
		if len(container.Networks) > 0 {
			publicIP := container.Networks[0].PublicIPv4Address
			privateIPs := container.Networks[0].IPv4Addresses

			// Set Public IP if available
			if publicIP != "" {
				instanceDetails.PublicIP = publicIP
			}

			// Set Private IP if available
			if len(privateIPs) > 0 {
				instanceDetails.PrivateIP = privateIPs[0]
			}
		}
	}

	// Set HostType and OS for DynamoDB (these may be known/static values)
	server_instance_id = taskID
	instanceDetails.HostType = "Fargate"
	server_environment = "Fargate"
	instanceDetails.OS = server_operating_system
	server_public_ip = getPublicIP()
	return instanceDetails, nil
}

// Function to update DynamoDB asynchronously
func updateDynamoDB(details InstanceDetails) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("us-east-1"), // Replace with your desired region
	)
	if err != nil {
		panic("unable to load SDK config, " + err.Error())
	}

	// Initialize DynamoDB client with the configuration
	dbSvc = dynamodb.NewFromConfig(cfg)
	timestamp := time.Now().UTC().Format(time.RFC3339)

	input := &dynamodb.PutItemInput{
		TableName: aws.String(dynamoDBHostTableName),
		Item: map[string]types.AttributeValue{
			"instance_id":  &types.AttributeValueMemberS{Value: details.InstanceID},
			"host_type":    &types.AttributeValueMemberS{Value: details.HostType},
			"os":           &types.AttributeValueMemberS{Value: details.OS},
			"private_ip":   &types.AttributeValueMemberS{Value: details.PrivateIP},
			"public_ip":    &types.AttributeValueMemberS{Value: details.PublicIP},
			"region":       &types.AttributeValueMemberS{Value: details.Region},
			"time_started": &types.AttributeValueMemberS{Value: timestamp},
		},
	}

	go func() {
		_, err := dbSvc.PutItem(context.TODO(), input) // Passing context as required
		if err != nil {
			log.Printf("failed to log stream start to DynamoDB: %v", err)
		}
	}()

}

// Function to update the time_stopped attribute in DynamoDB when the server stops
func updateDynamoDBStopTime(server_instance_id string) {

	// Get the current time
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Prepare the update input
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(dynamoDBHostTableName),
		Key: map[string]types.AttributeValue{
			"instance_id": &types.AttributeValueMemberS{Value: server_instance_id},
		},
		UpdateExpression: aws.String("SET time_stopped = :time_stopped"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":time_stopped": &types.AttributeValueMemberS{Value: timestamp},
		},
	}

	// Perform the update operation
	_, err := dbSvc.UpdateItem(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to update time_stopped in DynamoDB: %v", err)
	}
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org?format=json")
	if err != nil {
		log.Printf("error fetching public IP: %v", err)
		return ""
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("error fetching public IP: %v", err)
		return ""
	}

	return result["ip"]
}
