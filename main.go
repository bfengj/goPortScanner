package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type TcpHeader struct {
	SourcePort    uint16
	DestPort      uint16
	Seq           uint32
	Ack           uint32
	Flags         uint16
	Window        uint16
	CheckSum      uint16
	UrgentPointer uint16
	optionAndFill uint32
}
type ScanTask struct {
	SourceIp   string
	DestIp     string
	SourcePort uint16
	DestPort   uint16
}

//协程池
type Pool struct {
	EntryChannel      chan *ScanTask // 对外的Task入口
	JobsChannel       chan *ScanTask // 内部的Task队列
	workerNum         int            // 协程池中最大的woker数量
	finishedWorkCount int
}

func (pool *Pool) worker() {
	for task := range pool.JobsChannel {
		go task.synScan()
		task.recvAS()
		pool.finishedWorkCount += 1
	}
}
func createPool(cap int) *Pool {
	pool := &Pool{
		EntryChannel: make(chan *ScanTask, 65536),
		JobsChannel:  make(chan *ScanTask, 65536),
		workerNum:    cap,
	}
	return pool
}

func (pool *Pool) run() {
	fmt.Println("[-] start scanning!!!")
	for i := 0; i < pool.workerNum; i++ {
		go pool.worker()
	}
	//fmt.Println(123)
	//go stop()

	for task := range pool.EntryChannel {
		pool.JobsChannel <- task
	}
	close(pool.JobsChannel)
	lastFinishedCount := pool.finishedWorkCount
	lastTime := time.Now().Unix()
	for !(pool.finishedWorkCount == pool.workerNum) {
		//nowFinishedCount := pool.finishedWorkCount
		nowTime := time.Now().Unix()
		if pool.finishedWorkCount == lastFinishedCount && nowTime-lastTime >= 30 {
			fmt.Println("[-] finished!")
			os.Exit(0)
		} else if pool.finishedWorkCount != lastFinishedCount {
			lastFinishedCount = pool.finishedWorkCount
			lastTime = nowTime
		}
	}
	fmt.Println("[-] finished!")
}
func stop() {

}
func checkError(err error) {
	if err != nil {
		panic(err)
	}
}
func ipToByteSlice(ip string) []byte {
	splitIp := strings.Split(ip, ".")
	res := make([]byte, 4)
	for key, value := range splitIp {
		num, _ := strconv.Atoi(value)
		res[key] = byte(num)
	}
	return res
	//fmt.Println(res)
}
func headerToByteSlice(header interface{}) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, header)
	checkError(err)
	return buf.Bytes()
}

//Tcp报文头部中校验和的计算
func checkSum(header *TcpHeader, task *ScanTask) uint16 {
	//sourceIp = "10.26.187.190"
	sourceIpByte := ipToByteSlice(task.SourceIp)
	destIpByte := ipToByteSlice(task.DestIp)
	pseudoHeader := []byte{
		sourceIpByte[0], sourceIpByte[1], sourceIpByte[2], sourceIpByte[3],
		destIpByte[0], destIpByte[1], destIpByte[2], destIpByte[3],
		0,
		6,
		0,
		24,
	}
	totalHeader := append(pseudoHeader, headerToByteSlice(header)...)
	sum := uint32(0)
	//fmt.Println(len(totalHeader))
	//fmt.Println(totalHeader)
	for i := 0; i < len(totalHeader); i += 2 {
		sum += uint32(uint16(totalHeader[i])<<8 | uint16(totalHeader[i+1]))
		sum = (sum >> 16) + (sum & 0xffff)
		sum += (sum >> 16)
	}
	//如果作为二元运算符是按位异或
	//如果是一元运算符是取反
	return ^uint16(sum)
}

//获取本次请求的源ip地址，用于在检验和中计算。
func getSourceIp() (sourceIp string) {
	addrs, err := net.InterfaceAddrs()
	checkError(err)
	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				//if ipnet.IP.To4() != nil && strings.HasPrefix(ipnet.IP.String(), "10.") {
				sourceIp = ipnet.IP.String()
			}
		}
	}
	//fmt.Println("sourceIp:", sourceIp)
	return
}
func (task *ScanTask) recvAS() {
	listenAddr, err := net.ResolveIPAddr("ip4", task.SourceIp) // 解析域名为ip

	checkError(err)
	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	checkError(err)
	defer conn.Close()
	var resultCount int = 0
	for {
		/*		if (portCount <= 100 && resultCount == portCount) || (portCount <= 1000 && resultCount >= int(float64(portCount)*0.8)) || (portCount <= 10000 && resultCount >= int(float64(portCount)*0.7)) || (portCount <= 65536 && resultCount >= int(float64(portCount)*0.6)) {
				fmt.Println("scan ok")
				os.Exit(0)
			}*/

		buf := make([]byte, 1024)

		_, addr, err := conn.ReadFrom(buf)
		port := uint16(buf[0])<<8 + uint16(buf[1])
		if port != task.DestPort {
			continue
		}

		if err != nil || addr.String() != task.DestIp {
			continue
		}
		resultCount += 1
		if 0x12 == buf[13] {
			fmt.Println(port, ": open")
			task.sendRST()
			//fmt.Println(6)
		}
		break
	}

}
func (task *ScanTask) sendRST() {
	conn, err := net.Dial("ip4:6", task.DestIp)
	checkError(err)
	//flag为R
	tcpHeader := &TcpHeader{
		task.SourcePort,
		task.DestPort,
		rand.Uint32(),
		uint32(0),
		//0110 000000 000100
		uint16(24580),
		uint16(20000),
		uint16(0),
		uint16(0),
		uint32(0),
	}
	tcpHeader.CheckSum = checkSum(tcpHeader, task)
	_, err = conn.Write(headerToByteSlice(tcpHeader))
	checkError(err)
	conn.Close()
	//fmt.Println(5)
}
func (task *ScanTask) synScan() {
	//go recv(task)
	//ip报头中协议字段值为6是TCP
	conn, err := net.Dial("ip4:6", task.DestIp)
	checkError(err)
	defer conn.Close()
	tcpHeader := &TcpHeader{
		task.SourcePort,
		task.DestPort,
		rand.Uint32(),
		uint32(0),
		//0110 000000 000010
		uint16(24578),
		uint16(20000),
		uint16(0),
		uint16(0),
		uint32(0),
	}
	tcpHeader.CheckSum = checkSum(tcpHeader, task)
	_, err = conn.Write(headerToByteSlice(tcpHeader))
	checkError(err)
}

var (
	help   bool
	ports  string
	destIp string
)

func init() {
	flag.BoolVar(&help, "h", false, "show the help")
	flag.StringVar(&ports, "p", "", "the port you want to scan") //1-1024
	flag.StringVar(&destIp, "d", "", "the ip you want to scan")
	flag.Parse()
	rand.Seed(time.Now().Unix())
}
func getRandomSourcePort() uint16 {
	r := rand.Intn(20000) + 30000
	return uint16(r)
}
func main() {
	if help {
		flag.PrintDefaults()
		return
	}
	portSlice := strings.Split(ports, "-")
	startPort, _ := strconv.Atoi(portSlice[0])
	endPort, _ := strconv.Atoi(portSlice[1])
	portCount := endPort - startPort + 1
	pool := createPool(portCount)
	sourceIp := getSourceIp()
	fmt.Println("[+] your source IP :", sourceIp)
	fmt.Println("[+] the scanning target IP :", destIp)
	fmt.Println("[+] create works...")
	go func() {
		for port := startPort; port <= endPort; port += 1 {
			task := &ScanTask{
				sourceIp,
				destIp,
				getRandomSourcePort(),
				uint16(port),
			}
			pool.EntryChannel <- task
		}
		close(pool.EntryChannel)
	}()
	pool.run()
	//time.Sleep(5 * time.Second)

}
