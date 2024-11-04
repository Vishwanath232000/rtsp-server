package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aler9/gortsplib"
	"github.com/aler9/gortsplib/pkg/base"
	"github.com/google/uuid"
	"github.com/pion/rtp"

	"github.com/bhaney/rtsp-simple-server/internal/conf"
	"github.com/bhaney/rtsp-simple-server/internal/externalcmd"
	"github.com/bhaney/rtsp-simple-server/internal/logger"
	"github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/aws/session"
	// "github.com/aws/aws-sdk-go/service/sqs"
)

//Add this global variable at the package level
var (
	// sqsSvc *sqs.SQS
	dbSvc  *dynamodb.DynamoDB

)

var activeSessionCount int
var countMutex sync.Mutex

// Add this init function to initialize the DynamoDB client
func init() {
    // Initialize AWS session
    sess := session.Must(session.NewSessionWithOptions(session.Options{
        SharedConfigState: session.SharedConfigEnable,
    }))

    dbSvc = dynamodb.New(sess)
	// sqsSvc = sqs.New(sess)
}
func getInstanceID() string {

	client := http.Client{
		Timeout: time.Second * 2,
	}
	resp, err := client.Get("http://169.254.169.254/latest/meta-data/instance-id")
	if err != nil {
		return "local-instance" // fallback for local testing
	}
	defer resp.Body.Close()
	
	instanceID, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "local-instance"
	}

	
	return string(instanceID)
	// return "12345"
}
const (
	pauseAfterAuthError = 2 * time.Second
)

type rtspSessionPathManager interface {
	publisherAdd(req pathPublisherAddReq) pathPublisherAnnounceRes
	readerAdd(req pathReaderAddReq) pathReaderSetupPlayRes
}

type rtspSessionParent interface {
	log(logger.Level, string, ...interface{})
}

type rtspSession struct {
	isTLS           bool
	protocols       map[conf.Protocol]struct{}
	session         *gortsplib.ServerSession
	author          *gortsplib.ServerConn
	externalCmdPool *externalcmd.Pool
	pathManager     rtspSessionPathManager
	parent          rtspSessionParent

	uuid       uuid.UUID
	created    time.Time
	path       *path
	stream     *stream
	state      gortsplib.ServerSessionState
	stateMutex sync.Mutex
	onReadCmd  *externalcmd.Cmd // read
}

func newRTSPSession(
	isTLS bool,
	protocols map[conf.Protocol]struct{},
	session *gortsplib.ServerSession,
	sc *gortsplib.ServerConn,
	externalCmdPool *externalcmd.Pool,
	pathManager rtspSessionPathManager,
	parent rtspSessionParent,
) *rtspSession {
	s := &rtspSession{
		isTLS:           isTLS,
		protocols:       protocols,
		session:         session,
		author:          sc,
		externalCmdPool: externalCmdPool,
		pathManager:     pathManager,
		parent:          parent,
		uuid:            uuid.New(),
		created:         time.Now(),
	}

	// s.log(logger.Info, "created by %v", s.author.NetConn().RemoteAddr())

	return s
}

// Close closes a Session.
func (s *rtspSession) close() {
	s.session.Close()
}

// isRTSPSession implements pathRTSPSession.
func (s *rtspSession) isRTSPSession() {}

func (s *rtspSession) safeState() gortsplib.ServerSessionState {
	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()
	return s.state
}

func (s *rtspSession) remoteAddr() net.Addr {
	return s.author.NetConn().RemoteAddr()
}

func (s *rtspSession) log(level logger.Level, format string, args ...interface{}) {
	id := hex.EncodeToString(s.uuid[:4])
	s.parent.log(level, "[session %s] "+format, append([]interface{}{id}, args...)...)
}

// onClose is called by rtspServer.
// 
func (s *rtspSession) onClose(err error) {
	if s.session.State() == gortsplib.ServerSessionStatePlay {
		if s.onReadCmd != nil {
			s.onReadCmd.Close()
			s.onReadCmd = nil
			s.log(logger.Info, "runOnRead command stopped")
		}
	}

	switch s.session.State() {
	case gortsplib.ServerSessionStatePrePlay, gortsplib.ServerSessionStatePlay:
		s.path.readerRemove(pathReaderRemoveReq{author: s})

	case gortsplib.ServerSessionStatePreRecord, gortsplib.ServerSessionStateRecord:
		s.path.publisherRemove(pathPublisherRemoveReq{author: s})
		
		// Only log to DynamoDB and print stop message for publishers
		timestamp := time.Now().UTC().Format(time.RFC3339)
		input := &dynamodb.UpdateItemInput{
			TableName: aws.String("sam-rtsp-streams"),
			Key: map[string]*dynamodb.AttributeValue{
				"adapter_wifimac": {
					S: aws.String(s.path.Name()),
				},
			},
			UpdateExpression: aws.String("SET time_stamp = :time_stamp, is_active = :is_active"),
			ConditionExpression: aws.String("is_active = :is_active_condition"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":time_stamp": {
					S: aws.String(timestamp),
				},
				":is_active": {
					BOOL: aws.Bool(false),
				},
				":is_active_condition": {
					BOOL: aws.Bool(true),
				},
			},
		}

		// Update DynamoDB asynchronously
		go func() {
			_, err := dbSvc.UpdateItem(input)
			if err != nil {
				s.log(logger.Error, "failed to log stream stop to DynamoDB: %v", err)
			}
		}()

		activeSessionCount--

		rtsp_path := s.path.Name()
		fmt.Println("[",rtsp_path,"]", ":", s.uuid, "<<< Stopped")
		fmt.Println("Active sessions: ","[",activeSessionCount,"]")
	}

	s.path = nil
	s.stream = nil
}

// onAnnounce is called by rtspServer.
func (s *rtspSession) onAnnounce(c *rtspConn, ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	res := s.pathManager.publisherAdd(pathPublisherAddReq{
		author:   s,
		pathName: ctx.Path,
		authenticate: func(
			pathIPs []fmt.Stringer,
			pathUser conf.Credential,
			pathPass conf.Credential,
		) error {
			return c.authenticate(ctx.Path, pathIPs, pathUser, pathPass, true, ctx.Request, ctx.Query)
		},
	})

	if res.err != nil {
		switch terr := res.err.(type) {
		case pathErrAuthNotCritical:
			s.log(logger.Debug, "non-critical authentication error: %s", terr.message)
			return terr.response, nil

		case pathErrAuthCritical:
			// wait some seconds to stop brute force attacks
			<-time.After(pauseAfterAuthError)

			return terr.response, errors.New(terr.message)

		default:
			return &base.Response{
				StatusCode: base.StatusBadRequest,
			}, res.err
		}
	}

	s.path = res.path

	s.stateMutex.Lock()
	s.state = gortsplib.ServerSessionStatePreRecord
	s.stateMutex.Unlock()

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onSetup is called by rtspServer.
func (s *rtspSession) onSetup(c *rtspConn, ctx *gortsplib.ServerHandlerOnSetupCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	// in case the client is setupping a stream with UDP or UDP-multicast, and these
	// transport protocols are disabled, gortsplib already blocks the request.
	// we have only to handle the case in which the transport protocol is TCP
	// and it is disabled.
	if ctx.Transport == gortsplib.TransportTCP {
		if _, ok := s.protocols[conf.Protocol(gortsplib.TransportTCP)]; !ok {
			return &base.Response{
				StatusCode: base.StatusUnsupportedTransport,
			}, nil, nil
		}
	}

	switch s.session.State() {
	case gortsplib.ServerSessionStateInitial, gortsplib.ServerSessionStatePrePlay: // play
		res := s.pathManager.readerAdd(pathReaderAddReq{
			author:   s,
			pathName: ctx.Path,
			authenticate: func(
				pathIPs []fmt.Stringer,
				pathUser conf.Credential,
				pathPass conf.Credential,
			) error {
				return c.authenticate(ctx.Path, pathIPs, pathUser, pathPass, false, ctx.Request, ctx.Query)
			},
		})

		if res.err != nil {
			switch terr := res.err.(type) {
			case pathErrAuthNotCritical:
				s.log(logger.Debug, "non-critical authentication error: %s", terr.message)
				return terr.response, nil, nil

			case pathErrAuthCritical:
				// wait some seconds to stop brute force attacks
				<-time.After(pauseAfterAuthError)

				return terr.response, nil, errors.New(terr.message)

			case pathErrNoOnePublishing:
				return &base.Response{
					StatusCode: base.StatusNotFound,
				}, nil, res.err

			default:
				return &base.Response{
					StatusCode: base.StatusBadRequest,
				}, nil, res.err
			}
		}

		s.path = res.path
		s.stream = res.stream

		if ctx.TrackID >= len(res.stream.tracks()) {
			return &base.Response{
				StatusCode: base.StatusBadRequest,
			}, nil, fmt.Errorf("track %d does not exist", ctx.TrackID)
		}

		s.stateMutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.stateMutex.Unlock()

		return &base.Response{
			StatusCode: base.StatusOK,
		}, res.stream.rtspStream, nil

	default: // record
		return &base.Response{
			StatusCode: base.StatusOK,
		}, nil, nil
	}
}

// onPlay is called by rtspServer.
// func (s *rtspSession) onPlay(ctx *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
// 	h := make(base.Header)

// 	if s.session.State() == gortsplib.ServerSessionStatePrePlay {
// 		s.path.readerStart(pathReaderStartReq{author: s})

// 		tracks := make(gortsplib.Tracks, len(s.session.SetuppedTracks()))
// 		n := 0
// 		for id := range s.session.SetuppedTracks() {
// 			tracks[n] = s.stream.tracks()[id]
// 			n++
// 		}

// 		s.log(logger.Info, "is reading from path '%s', with %s, %s",
// 			s.path.Name(),
// 			s.session.SetuppedTransport(),
// 			sourceTrackInfo(tracks))

// 		if s.path.Conf().RunOnRead != "" {
// 			s.log(logger.Info, "runOnRead command started")
// 			s.onReadCmd = externalcmd.NewCmd(
// 				s.externalCmdPool,
// 				s.path.Conf().RunOnRead,
// 				s.path.Conf().RunOnReadRestart,
// 				s.path.externalCmdEnv(),
// 				func(co int) {
// 					s.log(logger.Info, "runOnRead command exited with code %d", co)
// 				})
// 		}

// 		s.stateMutex.Lock()
// 		s.state = gortsplib.ServerSessionStatePlay
// 		s.stateMutex.Unlock()
// 	}

// 	return &base.Response{
// 		StatusCode: base.StatusOK,
// 		Header:     h,
// 	}, nil
// }
func (s *rtspSession) onPlay(ctx *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	h := make(base.Header)

	if s.session.State() == gortsplib.ServerSessionStatePrePlay {
		s.path.readerStart(pathReaderStartReq{author: s})

		tracks := make(gortsplib.Tracks, len(s.session.SetuppedTracks()))
		n := 0
		for id := range s.session.SetuppedTracks() {
			tracks[n] = s.stream.tracks()[id]
			n++
		}

		// Only log basic info for readers, no special formatting
		// s.log(logger.Info, "is reading from path '%s', with %s, %s",
		// 	s.path.Name(),
		// 	s.session.SetuppedTransport(),
		// 	sourceTrackInfo(tracks))

		if s.path.Conf().RunOnRead != "" {
			s.log(logger.Info, "runOnRead command started")
			s.onReadCmd = externalcmd.NewCmd(
				s.externalCmdPool,
				s.path.Conf().RunOnRead,
				s.path.Conf().RunOnReadRestart,
				s.path.externalCmdEnv(),
				func(co int) {
					s.log(logger.Info, "runOnRead command exited with code %d", co)
				})
		}

		s.stateMutex.Lock()
		s.state = gortsplib.ServerSessionStatePlay
		s.stateMutex.Unlock()
	}

	return &base.Response{
		StatusCode: base.StatusOK,
		Header:     h,
	}, nil
}

// onRecord is called by rtspServer.
// func (s *rtspSession) onRecord(ctx *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
// 	res := s.path.publisherStart(pathPublisherStartReq{
// 		author:             s,
// 		tracks:             s.session.AnnouncedTracks(),
// 		generateRTPPackets: false,
// 	})
// 	if res.err != nil {
// 		return &base.Response{
// 			StatusCode: base.StatusBadRequest,
// 		}, res.err
// 	}

// 	// s.log(logger.Info, "is publishing to path '%s', with %s, %s",
// 	// 	s.path.Name(),
// 	// 	s.session.SetuppedTransport(),
// 	// 	sourceTrackInfo(s.session.AnnouncedTracks()))
// 	fmt.Println(s.path.Name(),":" ,s.uuid ,">>> Started")
// 	// s.log(logger.Info,"[%s]: %s >>> Started",s.path.Name(),s.uuid)

	

// 	// Send message to SQS
// 	sqsInput := &sqs.SendMessageInput{
// 		MessageBody: aws.String(fmt.Sprintf(`{"path": "%s"}`, s.path.Name())),
// 		QueueUrl:    aws.String("https://sqs.us-east-1.amazonaws.com/992382678727/stream_server_queue"),  // Replace with your SQS queue URL
// 	}

// 	sqsResp, err := sqsSvc.SendMessage(sqsInput)  
// 	if err != nil {
// 		s.log(logger.Error, "failed to send message to SQS: %v", err)
// 		return &base.Response{
// 			StatusCode: base.StatusInternalServerError,
// 		}, err
// 	}

// 	// Use SQS message ID and timestamp
// 	messageID := *sqsResp.MessageId
// 	timestamp := time.Now().UTC().Format(time.RFC3339)

// 	// Prepare DynamoDB input 
// 	input := &dynamodb.PutItemInput{
// 		TableName: aws.String("server_stream_table"),  // Replace with your DynamoDB table name
// 		Item: map[string]*dynamodb.AttributeValue{
// 			"session_Id": {
// 				S: aws.String(s.uuid.String()),
// 			},
// 			"instance_ID": {
// 				S: aws.String(getInstanceID()),
// 			},
// 			"stream_url": {
// 				S: aws.String(s.path.Name()),
// 			},
// 			"stream_start_time": {
// 				S: aws.String(timestamp),
// 			},
// 			"status": {
// 				S: aws.String("Streaming"),
// 			},
// 			"sqs_message_id": { 
// 				S: aws.String(messageID),
// 			},
// 			"message_sent_time": { 
// 				S: aws.String(timestamp),
// 			},
// 		},
// 	}

// 	// Asynchronously log to DynamoDB to avoid blocking the main flow
// 	go func() {
// 		_, err := dbSvc.PutItem(input)
// 		if err != nil {
// 			s.log(logger.Error, "failed to log stream start to DynamoDB: %v", err)
// 		}
// 	}()

// 	s.stream = res.stream

// 	s.stateMutex.Lock()
// 	s.state = gortsplib.ServerSessionStateRecord
// 	s.stateMutex.Unlock()

// 	return &base.Response{
// 		StatusCode: base.StatusOK,
// 	}, nil
// }
func (s *rtspSession) onRecord(ctx *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	res := s.path.publisherStart(pathPublisherStartReq{
		author:             s,
		tracks:             s.session.AnnouncedTracks(),
		generateRTPPackets: false,
	})
	if res.err != nil {
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, res.err
	}

	// Log publisher start
	fmt.Println("[",s.path.Name(),"]",":", s.uuid, ">>> Started")

	// // Send message to SQS for publishers
	// sqsInput := &sqs.SendMessageInput{
	// 	MessageBody: aws.String(fmt.Sprintf(`{"path": "%s"}`, s.path.Name())),
	// 	QueueUrl:    aws.String("https://sqs.us-east-1.amazonaws.com/992382678727/stream_server_queue"),
	// }

	// sqsResp, err := sqsSvc.SendMessage(sqsInput)
	// if err != nil {
	// 	s.log(logger.Error, "failed to send message to SQS: %v", err)
	// 	return &base.Response{
	// 		StatusCode: base.StatusInternalServerError,
	// 	}, err
	// }

	// Log to DynamoDB for publishers
	timestamp := time.Now().UTC().Format(time.RFC3339)
	input := &dynamodb.PutItemInput{
		TableName: aws.String("sam-rtsp-streams"),
		Item: map[string]*dynamodb.AttributeValue{
			"adapter_wifimac": {
				S: aws.String(s.path.Name()),
			},
			"is_active": {
				BOOL: aws.Bool(true),
			},
			"rstp_server_id1": {
				S: aws.String(getInstanceID()),
			},
			"session_id": {
				S: aws.String(s.uuid.String()),
			},
			"streamer_ip_address": {
				S: aws.String(s.author.NetConn().RemoteAddr().String()),
			},
			"time_stamp": {
				S: aws.String(timestamp),
			},
		},
	}

	go func() {
		_, err := dbSvc.PutItem(input)
		if err != nil {
			s.log(logger.Error, "failed to log stream start to DynamoDB: %v", err)
		}
	}()

	s.stream = res.stream

	s.stateMutex.Lock()
	s.state = gortsplib.ServerSessionStateRecord
	s.stateMutex.Unlock()
	activeSessionCount++
	fmt.Println("Active sessions: ","[",activeSessionCount,"]")
	

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onPause is called by rtspServer.
func (s *rtspSession) onPause(ctx *gortsplib.ServerHandlerOnPauseCtx) (*base.Response, error) {
	switch s.session.State() {
	case gortsplib.ServerSessionStatePlay:
		if s.onReadCmd != nil {
			s.log(logger.Info, "runOnRead command stopped")
			s.onReadCmd.Close()
		}

		s.path.readerStop(pathReaderStopReq{author: s})

		s.stateMutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.stateMutex.Unlock()

	case gortsplib.ServerSessionStateRecord:
		s.path.publisherStop(pathPublisherStopReq{author: s})

		s.stateMutex.Lock()
		s.state = gortsplib.ServerSessionStatePreRecord
		s.stateMutex.Unlock()
	}

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onReaderData implements reader.
func (s *rtspSession) onReaderData(data data) {
	// packets are routed to the session by gortsplib.ServerStream.
}

// apiReaderDescribe implements reader.
func (s *rtspSession) apiReaderDescribe() interface{} {
	var typ string
	if s.isTLS {
		typ = "rtspsSession"
	} else {
		typ = "rtspSession"
	}

	return struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}{typ, s.uuid.String()}
}

// apiSourceDescribe implements source.
func (s *rtspSession) apiSourceDescribe() interface{} {
	var typ string
	if s.isTLS {
		typ = "rtspsSession"
	} else {
		typ = "rtspSession"
	}

	return struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}{typ, s.uuid.String()}
}

// onPacketRTP is called by rtspServer.
func (s *rtspSession) onPacketRTP(ctx *gortsplib.ServerHandlerOnPacketRTPCtx) {
	var err error

	switch s.session.AnnouncedTracks()[ctx.TrackID].(type) {
	case *gortsplib.TrackH264:
		err = s.stream.writeData(&dataH264{
			trackID:    ctx.TrackID,
			rtpPackets: []*rtp.Packet{ctx.Packet},
			ntp:        time.Now(),
		})

	case *gortsplib.TrackMPEG4Audio:
		err = s.stream.writeData(&dataMPEG4Audio{
			trackID:    ctx.TrackID,
			rtpPackets: []*rtp.Packet{ctx.Packet},
			ntp:        time.Now(),
		})

	default:
		err = s.stream.writeData(&dataGeneric{
			trackID:    ctx.TrackID,
			rtpPackets: []*rtp.Packet{ctx.Packet},
			ntp:        time.Now(),
		})
	}

	if err != nil {
		s.log(logger.Warn, "%v", err)
	}
}

// onDecodeError is called by rtspServer.
func (s *rtspSession) onDecodeError(ctx *gortsplib.ServerHandlerOnDecodeErrorCtx) {
	s.log(logger.Warn, "%v", ctx.Error)
}
