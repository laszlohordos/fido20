package main

import (
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	MAX_SEQUENCE = uint8('\x7f')
	//Commands
	PING      byte = '\x81'
	KEEPALIVE byte = '\x82'
	MSG       byte = '\x83'
	ERROR     byte = '\xbf'

	//Error
	ERR_INVALID_CMD byte = '\x01' //The command in the request is unknown/invalid
	ERR_INVALID_PAR byte = '\x02' //The parameter(s) of the command is/are invalid or missing
	ERR_INVALID_LEN byte = '\x03' //The length of the request is invalid
	ERR_INVALID_SEQ byte = '\x04' //The sequence number is invalid
	ERR_REQ_TIMEOUT byte = '\x05' //The request timed out
	NA1             byte = '\x06' //Value reserved (HID)
	NA2             byte = '\x0a' //Value reserved (HID)
	NA3             byte = '\x0b' //Value reserved (HID)
	ERR_OTHER       byte = '\x7f' //Other, unspecified error

)

type (
	Request struct {
		sync.RWMutex
		cmd      byte
		data     []byte
		cache    map[int8][]byte
		size     uint16
		pos      int
		received int
	}

	Response struct {
		Status byte
		Data   []byte
	}

	FidoError struct {
		code byte
		msg  string
	}
)

func (r *Response) Process(maxLen int) [][]byte {
	bits := len(r.Data)
	if maxLen >= bits+3 {
		frame := make([]byte, bits+3)
		frame[0] = r.Status
		binary.BigEndian.PutUint16(frame[1:3], uint16(bits))
		copy(frame[3:], r.Data)
		return [][]byte{frame}
	} else {
		frameNumber := bits / (maxLen - 1)
		bits = (frameNumber * maxLen) + 2
		frameNumber = bits / maxLen
		mod := bits % maxLen

		if mod != 0 {
			frameNumber += 1
		}
		frames := make([][]byte, frameNumber)
		position := 0
		for i := 0; i < frameNumber; i++ {
			var frame []byte
			if i == 0 {
				//First
				frame = make([]byte, maxLen)
				frame[0] = r.Status
				binary.BigEndian.PutUint16(frame[1:3], uint16(len(r.Data)))
				copy(frame[3:], r.Data[position:maxLen-3])
				position += maxLen - 3
			} else if i == frameNumber-1 {
				//last
				frame = make([]byte, len(r.Data)-position+1)
				frame[0] = byte(i - 1)
				copy(frame[1:], r.Data[position:])
				position += maxLen - 1
			} else {
				frame = make([]byte, maxLen)
				frame[0] = byte(i - 1)
				copy(frame[1:], r.Data[position:position+maxLen-1])
				position += maxLen - 1
			}
			frames[i] = frame
		}

		return frames
	}
}

func (e *FidoError) Error() string {
	return fmt.Sprintf("FidoError(%02X) %s", e.code, e.msg)
}

func (e *FidoError) ToResponse() *Response {
	return &Response{
		Status: ERROR,
		Data:   []byte{e.code},
	}
}

func (r *Request) Data() ([]byte, error) {
	if r.cache != nil {
		r.Lock()
		defer r.Unlock()
		for i := int8(0); i < int8(len(r.cache)); i++ {
			if v, ok := r.cache[i]; ok {
				r.pos += copy(r.data[r.pos:], v)
			} else {
				return nil, fmt.Errorf("Missing packet sequence=[%d]", i)
			}
		}
		r.cache = nil
	}
	return r.data, nil
}

func (r *Request) Receive(data []byte) (bool, *FidoError) {
	r.Lock()
	defer r.Unlock()
	if data == nil || len(data) < 1 {
		return false, &FidoError{code: ERR_INVALID_LEN, msg: "short"}
	}

	first := uint8(data[0])
	if r.cmd != '\x00' && first > MAX_SEQUENCE {
		return false, &FidoError{code: ERR_INVALID_SEQ}
	}

	if r.cmd == '\x00' {
		//First frame
		if len(data) < 3 {
			return false, &FidoError{code: ERR_INVALID_LEN, msg: "short3"}
		}

		switch first {
		case PING:
			r.cmd = first
		case KEEPALIVE:
			r.cmd = first
		case MSG:
			r.cmd = first
		default:
			return false, &FidoError{code: ERR_INVALID_CMD}
		}

		r.size = binary.BigEndian.Uint16(data[1:3])
		r.data = make([]byte, r.size)
		r.received = copy(r.data, data[3:])
		r.pos = r.received
	} else {
		//Additional frame

		if r.cache == nil {
			r.cache = make(map[int8][]byte, int(r.size)/len(r.data)+1)
		}
		r.cache[int8(first)] = data[1:]
		r.received += len(data) - 1
	}
	if r.received > int(r.size) {
		return false, &FidoError{code: ERR_INVALID_LEN, msg: "long"}
	}
	return r.received != int(r.size), nil
}
