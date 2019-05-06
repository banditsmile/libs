<?php

class dnsARecord{

    protected $rawOffset = 0;
    protected $rawBuffer = '';
    protected $responseHeaderLen = 12;
    protected $responseRecordHeaderLen = 10;
    protected $responseHeader = null;

    /**
     * @param string $question
     * @return bool|string
     * @throws \Exception
     */
    protected function request($question = '')
    {
        //A记录查询
        $typeId = 1;
        $host = 'ns1.he.net';
        $port = 53;
        $timeout = 60;

        if (!$socket = @fsockopen($host, $port, $errno, $errstr, $timeout)) {
            throw new Exception("Failed to open socket to " . $host);
        }

        // Split Into Labels
        $labels = explode(".", $question);
        $question_binary = "";
        for ($a = 0; $a < count($labels); $a++) {
            $size = strlen($labels[$a]);
            $question_binary .= pack("C", $size); // size byte first
            $question_binary .= $labels[$a]; // then the label
        }
        // end it off
        $question_binary .= pack("C", 0);

        // generate the ID
        $id = rand(1, 255) | (rand(0, 255) << 8);

        // Set standard codes and flags
        // recursion & queryspecmask | authenticated data
        $flags = (0x0100 & 0x0300) | 0x0020;

        // opcode
        $opcode = 0x0000;

        // Build the header
        $header = "";
        $header .= pack("n", $id);
        $header .= pack("n", $opcode | $flags);
        $header .= pack("nnnn", 1, 0, 0, 0);
        $header .= $question_binary;
        $header .= pack("n", $typeId);
        $header .= pack("n", 0x0001); // internet class
        $headerSize = strlen($header);
        $headerSizeBin = pack("n", $headerSize);


        // write the socket
        if (!fwrite($socket, $headerSizeBin)) {
            fclose($socket);
            throw new Exception("Failed to write question length to TCP socket");
        }
        if (!fwrite($socket, $header, $headerSize)) {
            fclose($socket);
            throw new Exception("Failed to write question to TCP socket");
        }
        if (!$returnSize = fread($socket, 2)) {
            fclose($socket);
        }
        $tmpLen = unpack("nlength", $returnSize);
        $dataSize = $tmpLen['length'];
        if (!$this->rawBuffer = fread($socket, $dataSize)) {
            fclose($socket);
            throw new Exception("Failed to read data buffer");
        }
        fclose($socket);
        return $this->rawBuffer;
    }



    /**
     * 读取数据
     *
     * @param $length
     * @param  $offset
     *
     * @return bool|string
     */
    protected function readBuffer($length, $offset=null)
    {
        if (is_numeric($offset)) {
            $str = substr($this->rawBuffer, $offset, $length);
        } else {
            $str = substr($this->rawBuffer, $this->rawOffset, $length);
            $this->rawOffset += $length;
        }

        return $str;
    }

    /**
     * 解析响应数据
     *
     * @return array
     * @throws \Exception
     */
    public function parseResponse()
    {
        $bufferSize = strlen($this->rawBuffer);
        if ($bufferSize < $this->responseHeaderLen) {
            throw new Exception("DNS query return buffer too small");
        }

        $header = $this->readResponseHeader();
        var_dump($this->rawOffset);
        $this->readResponseQuestion();
        var_dump($this->rawOffset);
        $records = [];
        for ($a=0;$a<$header['ancount'];$a++) {
            var_dump($this->rawOffset);
            $records[] = $this->readRecord();
        }
        return ['header'=>$header,'records'=>$records];
    }

    /**
     * 解析响应资源记录
     *
     * @return array
     */
    public function readRecord()
    {
        return [
            'domain' =>$this->readRecordDomain(),
            'header'  =>$this->readRecordHeader(),
            'data'    =>$this->readRecordData()
        ];
    }

    /**
     * 解析响应资源记录标签(请求的域名)
     *
     * @return string
     */
    private function readRecordDomain()
    {
        $buffer = $this->rawBuffer;
        $count = 0;
        $labels = $this->ReadDomainLabels($buffer, $this->rawOffset, $count);
        $domain = implode(".", $labels);
        $this->rawOffset += $count;
        return $domain;
    }

    /**
     * @param     $buffer
     * @param     $offset
     * @param int $counter
     * @return array
     */
    private function ReadDomainLabels($buffer, $offset, &$counter = 0)
    {
        $labels = array();
        $startOffset = $offset;
        $return = false;
        while (!$return) {
            $label_len = ord($this->readBuffer(1, $offset++));
            if ($label_len <= 0) { // end of data
                $return = true;
            } else if ($label_len < 64) { // uncompressed data
                var_dump($buffer);
                $labels[] = $this->readBuffer($label_len, $offset);
                var_dump($labels);
                $offset += $label_len;

            } else { // label_len>=64 -- pointer
                $nextItem = $this->readBuffer(1, $offset++);
                $pointer_offset = (($label_len & 0x3f) << 8) + ord($nextItem);
                $pointer_labels = $this->ReadDomainLabels($buffer, $pointer_offset);
                foreach ($pointer_labels as $ptr_label) {
                    $labels[] = $ptr_label;
                }
                $return = true;
            }
        }
        $counter = $offset - $startOffset;
        return $labels;
    }

    /**
     * 解析响应资源记录头
     *
     * @return array
     */
    public function readRecordHeader()
    {
        var_dump($this->rawOffset);
        // 10 byte header
        $ans_header_bin = $this->readBuffer($this->responseRecordHeaderLen);
        $ans_header = unpack("ntype/nclass/Nttl/nlength", $ans_header_bin);
        return $ans_header;
    }

    /**
     * 解析响应资源记录数据
     *
     * @return string
     */
    public function readRecordData()
    {
        var_dump($this->rawOffset);
        $dataBin = $this->readBuffer(4);
        $ip = implode(".", unpack("Ca/Cb/Cc/Cd", $dataBin));
        return $ip;
    }

    /**
     * 解析响应头部
     *
     * @return array
     */
    public function readResponseHeader()
    {
        $rawHeader = $this->readBuffer($this->responseHeaderLen);
        $this->responseHeader
            = unpack("nid/nflags/nqdcount/nancount/nnscount/narcount", $rawHeader);
        $flags = sprintf("%016b\n", $this->responseHeader['flags']);
        $flagData = [
            'authorative'        => $flags{5}=='1',
            'truncated'          => $flags{6}=='1',
            'recursionRequested' => $flags{7}=='1',
            'recursionAvailable' => $flags{8}=='1',
            'authenticated'      => $flags{10}=='1',
            'dnssecAware'        => $flags{11}=='1',
            'answers'            => $this->responseHeader['ancount'],
        ];
        $this->responseHeader['flagData'] = $flagData;
        return $this->responseHeader;
    }

    /**
     *
     */
    public function readResponseQuestion()
    {
        // Deal with the header question data
        if ($this->responseHeader['qdcount'] > 0) {
            $q = '';
            for ($a = 0; $a < $this->responseHeader['qdcount']; $a++) {
                $c = 1;
                while ($c != 0) {
                    var_dump($this->rawOffset);

                    $c = hexdec(bin2hex($this->readBuffer(1)));
                    $q .= $c;
                    echo $c,PHP_EOL;
                }
                var_dump($this->rawOffset);
                $this->readBuffer(4);
                var_dump($this->rawOffset);
            }
        }
    }

    /**
     * @param $question
     * @return array
     */
    public function query($question)
    {
        $this->request($question);
        $response  = $this->parseResponse();
        return $response;
    }
}

$dns = new dnsARecord();
$result = $dns->query('series.ink');
var_export($result);
