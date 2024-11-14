package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bhaney/rtsp-simple-server/internal/conf"
	"github.com/bhaney/rtsp-simple-server/internal/externalcmd"
	"github.com/bhaney/rtsp-simple-server/internal/logger"

	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type rtmpServerAPIConnsListItem struct {
	Created       time.Time `json:"created"`
	RemoteAddr    string    `json:"remoteAddr"`
	State         string    `json:"state"`
	BytesReceived uint64    `json:"bytesReceived"`
	BytesSent     uint64    `json:"bytesSent"`
}

type rtmpServerAPIConnsListData struct {
	Items map[string]rtmpServerAPIConnsListItem `json:"items"`
}

type rtmpServerAPIConnsListRes struct {
	data *rtmpServerAPIConnsListData
	err  error
}

type rtmpServerAPIConnsListReq struct {
	res chan rtmpServerAPIConnsListRes
}

type rtmpServerAPIConnsKickRes struct {
	err error
}

type rtmpServerAPIConnsKickReq struct {
	id  string
	res chan rtmpServerAPIConnsKickRes
}

type rtmpServerParent interface {
	Log(logger.Level, string, ...interface{})
}

type InstanceDetails struct {
	InstanceID string `json:"instance_id"`
	HostType   string `json:"host_type"`
	OS         string `json:"os"`
	PrivateIP  string `json:"private_ip"`
	PublicIP   string `json:"public_ip"`
	Region     string `json:"region"`
}
type rtmpServer struct {
	externalAuthenticationURL string
	readTimeout               conf.StringDuration
	writeTimeout              conf.StringDuration
	readBufferCount           int
	isTLS                     bool
	rtspAddress               string
	runOnConnect              string
	runOnConnectRestart       bool
	externalCmdPool           *externalcmd.Pool
	metrics                   *metrics
	pathManager               *pathManager
	parent                    rtmpServerParent

	ctx       context.Context
	ctxCancel func()
	wg        sync.WaitGroup
	ln        net.Listener
	conns     map[*rtmpConn]struct{}

	// in
	chConnClose    chan *rtmpConn
	chAPIConnsList chan rtmpServerAPIConnsListReq
	chAPIConnsKick chan rtmpServerAPIConnsKickReq
}

func newRTMPServer(
	parentCtx context.Context,
	externalAuthenticationURL string,
	address string,
	readTimeout conf.StringDuration,
	writeTimeout conf.StringDuration,
	readBufferCount int,
	isTLS bool,
	serverCert string,
	serverKey string,
	rtspAddress string,
	runOnConnect string,
	runOnConnectRestart bool,
	externalCmdPool *externalcmd.Pool,
	metrics *metrics,
	pathManager *pathManager,
	parent rtmpServerParent,
) (*rtmpServer, error) {
	ln, err := func() (net.Listener, error) {
		if !isTLS {
			return net.Listen("tcp", address)
		}

		cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
		if err != nil {
			return nil, err
		}

		return tls.Listen("tcp", address, &tls.Config{Certificates: []tls.Certificate{cert}})
	}()
	if err != nil {
		return nil, err
	}

	ctx, ctxCancel := context.WithCancel(parentCtx)

	s := &rtmpServer{
		externalAuthenticationURL: externalAuthenticationURL,
		readTimeout:               readTimeout,
		writeTimeout:              writeTimeout,
		readBufferCount:           readBufferCount,
		rtspAddress:               rtspAddress,
		runOnConnect:              runOnConnect,
		runOnConnectRestart:       runOnConnectRestart,
		isTLS:                     isTLS,
		externalCmdPool:           externalCmdPool,
		metrics:                   metrics,
		pathManager:               pathManager,
		parent:                    parent,
		ctx:                       ctx,
		ctxCancel:                 ctxCancel,
		ln:                        ln,
		conns:                     make(map[*rtmpConn]struct{}),
		chConnClose:               make(chan *rtmpConn),
		chAPIConnsList:            make(chan rtmpServerAPIConnsListReq),
		chAPIConnsKick:            make(chan rtmpServerAPIConnsKickReq),
	}

	s.log(logger.Info, "listener opened on %s", address)

	if s.metrics != nil {
		s.metrics.rtmpServerSet(s)
	}

	s.wg.Add(1)
	go s.run()

	return s, nil
}

func (s *rtmpServer) log(level logger.Level, format string, args ...interface{}) {
	label := func() string {
		if s.isTLS {
			return "RTMPS"
		}
		return "RTMP"
	}()
	s.parent.Log(level, "[%s] "+format, append([]interface{}{label}, args...)...)
}

func (s *rtmpServer) close() {
	s.log(logger.Info, "listener is closing")
	s.ctxCancel()
	s.wg.Wait()
	updateDynamoDBStopTime(server_instance_id)
}

func (s *rtmpServer) run() {
	defer s.wg.Done()

	s.wg.Add(1)
	connNew := make(chan net.Conn)
	acceptErr := make(chan error)
	go func() {
		defer s.wg.Done()
		err := func() error {
			for {
				conn, err := s.ln.Accept()
				if err != nil {
					return err
				}

				select {
				case connNew <- conn:
				case <-s.ctx.Done():
					conn.Close()
				}
			}
		}()

		select {
		case acceptErr <- err:
		case <-s.ctx.Done():
		}
	}()

outer:
	for {
		select {
		case err := <-acceptErr:
			s.log(logger.Error, "%s", err)
			break outer

		case nconn := <-connNew:
			c := newRTMPConn(
				s.ctx,
				s.isTLS,
				s.externalAuthenticationURL,
				s.rtspAddress,
				s.readTimeout,
				s.writeTimeout,
				s.readBufferCount,
				s.runOnConnect,
				s.runOnConnectRestart,
				&s.wg,
				nconn,
				s.externalCmdPool,
				s.pathManager,
				s)
			s.conns[c] = struct{}{}

		case c := <-s.chConnClose:
			if _, ok := s.conns[c]; !ok {
				continue
			}
			delete(s.conns, c)

		case req := <-s.chAPIConnsList:
			data := &rtmpServerAPIConnsListData{
				Items: make(map[string]rtmpServerAPIConnsListItem),
			}

			for c := range s.conns {
				data.Items[c.uuid.String()] = rtmpServerAPIConnsListItem{
					Created:    c.created,
					RemoteAddr: c.remoteAddr().String(),
					State: func() string {
						switch c.safeState() {
						case rtmpConnStateRead:
							return "read"

						case rtmpConnStatePublish:
							return "publish"
						}
						return "idle"
					}(),
					BytesReceived: c.conn.BytesReceived(),
					BytesSent:     c.conn.BytesSent(),
				}
			}

			req.res <- rtmpServerAPIConnsListRes{data: data}

		case req := <-s.chAPIConnsKick:
			res := func() bool {
				for c := range s.conns {
					if c.uuid.String() == req.id {
						delete(s.conns, c)
						c.close()
						return true
					}
				}
				return false
			}()
			if res {
				req.res <- rtmpServerAPIConnsKickRes{}
			} else {
				req.res <- rtmpServerAPIConnsKickRes{fmt.Errorf("not found")}
			}

		case <-s.ctx.Done():
			break outer
		}
	}

	s.ctxCancel()

	s.ln.Close()

	if s.metrics != nil {
		s.metrics.rtmpServerSet(s)
	}
}

// connClose is called by rtmpConn.
func (s *rtmpServer) connClose(c *rtmpConn) {
	select {
	case s.chConnClose <- c:
	case <-s.ctx.Done():
	}
}

// apiConnsList is called by api.
func (s *rtmpServer) apiConnsList() rtmpServerAPIConnsListRes {
	req := rtmpServerAPIConnsListReq{
		res: make(chan rtmpServerAPIConnsListRes),
	}

	select {
	case s.chAPIConnsList <- req:
		return <-req.res

	case <-s.ctx.Done():
		return rtmpServerAPIConnsListRes{err: fmt.Errorf("terminated")}
	}
}

// apiConnsKick is called by api.
func (s *rtmpServer) apiConnsKick(id string) rtmpServerAPIConnsKickRes {
	req := rtmpServerAPIConnsKickReq{
		id:  id,
		res: make(chan rtmpServerAPIConnsKickRes),
	}

	select {
	case s.chAPIConnsKick <- req:
		return <-req.res

	case <-s.ctx.Done():
		return rtmpServerAPIConnsKickRes{err: fmt.Errorf("terminated")}
	}
}

var dynamoDBHostTableName string
var server_instance_id string

// init is called automatically when the package is loaded
func init() {
	dynamoDBHostTableName = os.Getenv("DYNAMODB_HOST_INFO_TABLE_NAME")
	if dynamoDBHostTableName == "" {
		log.Fatal("DYNAMODB_TABLE_NAME environment variable is not set")
		dynamoDBHostTableName = "sam-rtsp-server-hosts"
	}
	// Fetch EC2 instance metadata and start background DynamoDB update
	go func() {
		instanceDetails, err := getInstanceMetadata()
		if err != nil {
			log.Printf("Failed to get instance metadata: %v", err)
			return
		}

		// Start the background update to DynamoDB
		log.Println("Starting background DynamoDB update")
		updateDynamoDB(instanceDetails)
	}()
}

// Fetch EC2 instance metadata
// Function to fetch EC2 instance metadata with IMDSv2 token
const EC2APIURL = "http://169.254.169.254/latest/meta-data/"
const EC2MetadataTokenURI = "http://169.254.169.254/latest/api/token"
const EC2MetadataTokenTTL = "21600"

func getMetadataToken() (string, error) {
	req, err := http.NewRequest("PUT", EC2MetadataTokenURI, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve token: %v", resp.Status)
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %v", err)
	}

	return string(token), nil
}

// Function to get the IMDSv2 token
func getMetadataUsingToken(token string) (map[string]string, error) {
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
	token, err := getMetadataToken()
	if err != nil {
		return instanceDetails, fmt.Errorf("failed to get metadata token: %v", err)
	}

	// Get all metadata using the token
	metadata, err := getMetadataUsingToken(token)
	if err != nil {
		return instanceDetails, fmt.Errorf("failed to get instance metadata: %v", err)
	}

	// Populate the InstanceDetails struct with metadata
	instanceDetails.InstanceID = metadata["instance-id"]
	instanceDetails.Region = metadata["placement/availability-zone"]
	instanceDetails.PublicIP = metadata["public-ipv4"]
	instanceDetails.PrivateIP = metadata["local-ipv4"]
	instanceDetails.HostType = "EC2"       // Hardcoded for simplicity, could be dynamic
	instanceDetails.OS = "Linux (assumed)" // Hardcoded as example
	server_instance_id = metadata["instance-id"]
	// Optionally, you can modify the region to remove the availability zone suffix, if needed
	instanceDetails.Region = strings.TrimSuffix(instanceDetails.Region, "a")

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
