package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
)

type Finding struct {
	Severity string `json:"severity"`
	Name     string `json:"name"`
	Detail   string `json:"detail"`
}

type XORCandidate struct {
	Key     int     `json:"key"`
	KeyHex  string  `json:"keyHex"`
	Ratio   float64 `json:"ratio"`
	Preview string  `json:"preview"`
}

type EntropyBlock struct {
	Offset  int     `json:"offset"`
	Entropy float64 `json:"entropy"`
}

type AnalysisResult struct {
	Filename          string         `json:"filename"`
	FileSize          int64          `json:"fileSize"`
	GlobalEntropy     float64        `json:"globalEntropy"`
	Findings          []Finding      `json:"findings"`
	XORCandidates     []XORCandidate `json:"xorCandidates"`
	RollingXOR        []XORCandidate `json:"rollingXOR"`
	EntropyBlocks     []EntropyBlock `json:"entropyBlocks"`
	HighEntropyBlocks int            `json:"highEntropyBlocks"`
	Strings           []string       `json:"strings"`
	CryptoStrings     []string       `json:"cryptoStrings"`
	HexDump           string         `json:"hexDump"`
	Error             string         `json:"error,omitempty"`
}

func calcEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
	h := 0.0
	n := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

type magicSig struct {
	offset int
	bytes  []byte
	name   string
	detail string
	sev    string
}

var signatures = []magicSig{
	{0, []byte{0x7f, 0x45, 0x4c, 0x46}, "ELF binary", "Linux/embedded ELF executable", "info"},
	{0, []byte{0x55, 0xAA}, "MBR / bootloader signature", "0x55AA boot sector magic at offset 0", "info"},
	{0, []byte{0x1f, 0x8b}, "GZIP compressed", "gzip stream — data is compressed, not encrypted", "med"},
	{0, []byte{0x42, 0x5a, 0x68}, "BZip2 compressed", "BZ2 magic bytes detected", "med"},
	{0, []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, "XZ compressed", "XZ stream magic — LZMA2 payload", "med"},
	{0, []byte{0x27, 0x05, 0x19, 0x56}, "U-Boot image", "uImage header — likely LZMA/gzip payload", "info"},
	{0, []byte{0x68, 0x73, 0x71, 0x73}, "SquashFS filesystem", "Compressed Linux filesystem (little-endian)", "info"},
	{0, []byte{0x73, 0x71, 0x73, 0x68}, "SquashFS filesystem", "Compressed Linux filesystem (big-endian)", "info"},
	{0, []byte{0x30, 0x82}, "DER certificate/key", "ASN.1 DER-encoded data — may contain RSA key material", "high"},
	{0, []byte{0x2d, 0x2d, 0x2d, 0x2d, 0x2d}, "PEM encoded data", "Base64 PEM block (certificate, private key, or encrypted payload)", "high"},
	{0, []byte{0x50, 0x4b, 0x03, 0x04}, "ZIP archive", "ZIP — may contain encrypted nested payloads", "med"},
	{0, []byte{0x52, 0x61, 0x72, 0x21}, "RAR archive", "RAR archive — check for password-protected entries", "med"},
	{0, []byte{0x4d, 0x5a}, "PE / DOS executable", "Windows PE or DOS executable header", "info"},
	{0, []byte{0xce, 0xfa, 0xed, 0xfe}, "Mach-O binary (32-bit)", "Apple Mach-O executable", "info"},
	{0, []byte{0xcf, 0xfa, 0xed, 0xfe}, "Mach-O binary (64-bit)", "Apple Mach-O 64-bit executable", "info"},
	{0, []byte{0xd0, 0xcf, 0x11, 0xe0}, "OLE2 compound file", "Microsoft compound document format", "info"},
}

func detectMagic(data []byte) []Finding {
	var out []Finding
	for _, s := range signatures {
		if s.offset+len(s.bytes) > len(data) {
			continue
		}
		match := true
		for i, b := range s.bytes {
			if data[s.offset+i] != b {
				match = false
				break
			}
		}
		if match {
			out = append(out, Finding{s.sev, "Magic: " + s.name, s.detail})
		}
	}
	return out
}

func extractStrings(data []byte, minLen int) []string {
	var strs []string
	cur := make([]byte, 0, 64)
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			cur = append(cur, b)
		} else {
			if len(cur) >= minLen {
				strs = append(strs, string(cur))
			}
			cur = cur[:0]
		}
	}
	if len(cur) >= minLen {
		strs = append(strs, string(cur))
	}
	return strs
}

func detectXOR(data []byte) []XORCandidate {
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	var results []XORCandidate
	for key := 1; key < 256; key++ {
		dec := make([]byte, len(sample))
		for i, b := range sample {
			dec[i] = b ^ byte(key)
		}
		printable := 0
		for _, b := range dec {
			if b >= 0x20 && b < 0x7f {
				printable++
			}
		}
		ratio := float64(printable) / float64(len(dec))
		if ratio > 0.65 {
			strs := extractStrings(dec, 5)
			if len(strs) > 3 {
				strs = strs[:3]
			}
			results = append(results, XORCandidate{
				Key:     key,
				KeyHex:  fmt.Sprintf("0x%02x", key),
				Ratio:   math.Round(ratio*1000) / 10,
				Preview: strings.Join(strs, ", "),
			})
		}
	}
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Ratio > results[i].Ratio {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	if len(results) > 3 {
		results = results[:3]
	}
	return results
}

func detectRollingXOR(data []byte) []XORCandidate {
	sample := data
	if len(sample) > 2048 {
		sample = sample[:2048]
	}
	var results []XORCandidate
	for ks := 2; ks <= 8; ks++ {
		if ks > len(sample) {
			break
		}
		key := sample[:ks]
		dec := make([]byte, len(sample))
		for i, b := range sample {
			dec[i] = b ^ key[i%ks]
		}
		printable := 0
		for _, b := range dec {
			if b >= 0x20 && b < 0x7f {
				printable++
			}
		}
		ratio := float64(printable) / float64(len(dec))
		if ratio > 0.60 {
			results = append(results, XORCandidate{
				Key:    ks,
				KeyHex: hex.EncodeToString(key),
				Ratio:  math.Round(ratio*1000) / 10,
			})
		}
	}
	if len(results) > 2 {
		results = results[:2]
	}
	return results
}

func hexDump(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		row := data[i:]
		if len(row) > 16 {
			row = row[:16]
		}
		sb.WriteString(fmt.Sprintf("%06x  ", i))
		hexPart := ""
		for j, b := range row {
			hexPart += fmt.Sprintf("%02x ", b)
			if j == 7 {
				hexPart += " "
			}
		}
		sb.WriteString(fmt.Sprintf("%-49s ", hexPart))
		for _, b := range row {
			if b >= 0x20 && b < 0x7f {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func analyse(data []byte, filename string) AnalysisResult {
	r := AnalysisResult{
		Filename: filename,
		FileSize: int64(len(data)),
	}
	r.GlobalEntropy = calcEntropy(data)

	const blockSize = 256
	for i := 0; i < len(data) && i < 64*256; i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		h := calcEntropy(data[i:end])
		r.EntropyBlocks = append(r.EntropyBlocks, EntropyBlock{i, math.Round(h*1000) / 1000})
		if h > 7.2 {
			r.HighEntropyBlocks++
		}
	}

	magicFindings := detectMagic(data)
	r.XORCandidates = detectXOR(data)
	r.RollingXOR = detectRollingXOR(data)
	r.Strings = extractStrings(data, 4)

	cryptoKw := []string{"aes", "des", "rsa", "key", "encrypt", "cipher", "iv", "salt", "crypt", "hmac", "sha", "md5", "pkcs"}
	for _, s := range r.Strings {
		lower := strings.ToLower(s)
		for _, kw := range cryptoKw {
			if strings.Contains(lower, kw) {
				r.CryptoStrings = append(r.CryptoStrings, s)
				break
			}
		}
	}
	r.HexDump = hexDump(data, 512)

	var findings []Finding
	h := r.GlobalEntropy
	switch {
	case h > 7.4:
		findings = append(findings, Finding{"high", "Very high entropy detected",
			fmt.Sprintf("%.3f bits/byte — consistent with AES-CBC, AES-CTR, ChaCha20, or similar block/stream cipher. Strongly compressed data (LZMA, LZ4) also reaches this level.", h)})
	case h > 7.0:
		findings = append(findings, Finding{"med", "Elevated entropy",
			fmt.Sprintf("%.3f bits/byte — possibly XOR-obfuscated, RC4-encrypted, or GZIP-compressed. May be a compressed firmware payload.", h)})
	case h > 5.5:
		findings = append(findings, Finding{"low", "Moderate entropy — mixed content",
			fmt.Sprintf("%.3f bits/byte — partially structured. Could contain encrypted sections within plaintext headers.", h)})
	default:
		findings = append(findings, Finding{"info", "Low entropy — mostly plaintext",
			fmt.Sprintf("%.3f bits/byte — file appears largely unencrypted. Suitable for direct static analysis.", h)})
	}

	findings = append(findings, magicFindings...)

	// U-Boot extra
	if len(data) >= 64 {
		sig := []byte{0x27, 0x05, 0x19, 0x56}
		match := true
		for i, b := range sig {
			if data[i] != b {
				match = false
				break
			}
		}
		if match && len(data) >= 16 {
			name := strings.TrimRight(string(data[32:64]), "\x00")
			dataSize := binary.BigEndian.Uint32(data[12:16])
			findings = append(findings, Finding{"info", "U-Boot header parsed",
				fmt.Sprintf("Image name: %q — payload size: %d bytes (0x%x), starts at offset 64", name, dataSize, dataSize)})
		}
	}

	if len(r.XORCandidates) > 0 {
		best := r.XORCandidates[0]
		findings = append(findings, Finding{"high",
			fmt.Sprintf("XOR key candidate: 0x%02x", best.Key),
			fmt.Sprintf("Single-byte XOR with key 0x%02x yields %.1f%% printable output. Strings: %s", best.Key, best.Ratio, best.Preview)})
	}
	if len(r.RollingXOR) > 0 {
		rx := r.RollingXOR[0]
		findings = append(findings, Finding{"med",
			fmt.Sprintf("Rolling XOR — %d-byte key candidate", rx.Key),
			fmt.Sprintf("Key bytes: %s — repeating XOR yields %.1f%% printable output", rx.KeyHex, rx.Ratio)})
	}
	if len(r.CryptoStrings) > 0 {
		preview := r.CryptoStrings
		if len(preview) > 6 {
			preview = preview[:6]
		}
		findings = append(findings, Finding{"med", "Crypto-related strings in binary", strings.Join(preview, " · ")})
	}

	nullRuns := 0
	for i := 0; i+7 < len(data) && i < 512; i++ {
		allNull := true
		for j := 0; j < 8; j++ {
			if data[i+j] != 0 {
				allNull = false
				break
			}
		}
		if allNull {
			nullRuns++
			i += 7
		}
	}
	if nullRuns > 4 {
		findings = append(findings, Finding{"info", "Null-byte padding regions",
			"Multiple zero-byte blocks in header — typical of ECB mode padding or uninitialised key storage."})
	}

	if len(data) > 16 {
		highCount := 0
		for _, b := range data[:16] {
			if b > 127 {
				highCount++
			}
		}
		if highCount > 12 {
			findings = append(findings, Finding{"med", "High-byte density header",
				"Many bytes >0x7F in the first 16 bytes — possible XOR or byte-substitution cipher."})
		}
	}

	checkLen := len(data)
	if checkLen > 4096 {
		checkLen = 4096
	}
	nonPrint := 0
	for _, b := range data[:checkLen] {
		if !unicode.IsPrint(rune(b)) && b != '\n' && b != '\r' && b != '\t' {
			nonPrint++
		}
	}
	nonPrintRatio := float64(nonPrint) / float64(checkLen)
	if nonPrintRatio > 0.85 && h < 7.0 {
		findings = append(findings, Finding{"med", "Binary data — not plaintext",
			fmt.Sprintf("%.1f%% of sampled bytes are non-printable. Structured binary or obfuscated data.", nonPrintRatio*100)})
	}

	if len(findings) == 0 {
		findings = append(findings, Finding{"info", "No strong indicators found",
			"File does not match common encryption signatures. Manual reverse engineering recommended."})
	}

	r.Findings = findings
	return r
}

func handleAnalyse(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	if err := req.ParseMultipartForm(64 << 20); err != nil {
		writeJSON(w, AnalysisResult{Error: "Parse error: " + err.Error()})
		return
	}
	file, header, err := req.FormFile("firmware")
	if err != nil {
		writeJSON(w, AnalysisResult{Error: "No file: " + err.Error()})
		return
	}
	defer file.Close()
	data := make([]byte, header.Size)
	file.Read(data)
	writeJSON(w, analyse(data, header.Filename))
}

func handleDecrypt(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	req.ParseMultipartForm(64 << 20)
	file, header, err := req.FormFile("firmware")
	if err != nil {
		http.Error(w, "no file", 400)
		return
	}
	defer file.Close()
	var keyVal int
	fmt.Sscanf(req.FormValue("key"), "%d", &keyVal)
	data := make([]byte, header.Size)
	file.Read(data)
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ byte(keyVal)
	}
	ext := filepath.Ext(header.Filename)
	base := strings.TrimSuffix(header.Filename, ext)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_xor0x%02x%s"`, base, keyVal, ext))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(out)
}

func handleStrings(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	req.ParseMultipartForm(64 << 20)
	file, header, err := req.FormFile("firmware")
	if err != nil {
		http.Error(w, "no file", 400)
		return
	}
	defer file.Close()
	data := make([]byte, header.Size)
	file.Read(data)
	strs := extractStrings(data, 4)
	base := strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_strings.txt"`, base))
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(strings.Join(strs, "\n")))
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}

const htmlPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firmware Encryption Analyser</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0f14;--bg2:#13151c;--bg3:#1a1d26;--bg4:#21253a;
  --border:#2a2f45;--text:#c8cdd8;--muted:#6b7494;
  --accent:#4f8ef7;--danger:#e05555;--warn:#e0a020;--ok:#3db87a;
  --font:'Cascadia Code','Fira Code','Consolas',monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.6;min-height:100vh}
h1{font-size:15px;font-weight:500;letter-spacing:0.05em;color:#fff}
.header{background:var(--bg2);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;gap:12px}
.logo{width:28px;height:28px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;color:#fff;font-weight:bold}
.sub{font-size:11px;color:var(--muted);margin-top:1px}
.main{padding:24px;max-width:960px;margin:0 auto}
.drop{border:1.5px dashed var(--border);border-radius:10px;padding:40px 24px;text-align:center;cursor:pointer;transition:background .15s,border-color .15s;background:var(--bg2);margin-bottom:20px}
.drop:hover,.drop.over{background:var(--bg3);border-color:var(--accent)}
.drop input{display:none}
.icon{font-size:36px;margin-bottom:10px}
.lbl{font-size:14px;color:#fff;font-weight:500}
.dsub{font-size:11px;color:var(--muted);margin-top:4px}
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:16px;overflow:hidden}
.panel-title{font-size:10px;letter-spacing:0.1em;color:var(--muted);padding:10px 16px;border-bottom:1px solid var(--border);text-transform:uppercase;background:var(--bg3)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;padding:14px 16px}
.metric{background:var(--bg3);border-radius:6px;padding:10px 14px}
.ml{font-size:10px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:0.05em}
.mv{font-size:20px;font-weight:500;color:#fff}
.mv.danger{color:var(--danger)}.mv.warn{color:var(--warn)}.mv.ok{color:var(--ok)}
.tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg3)}
.tab{padding:8px 16px;font-size:11px;cursor:pointer;color:var(--muted);border:none;background:none;font-family:var(--font);letter-spacing:0.05em;border-bottom:2px solid transparent;transition:color .1s;text-transform:uppercase}
.tab:hover{color:var(--text)}.tab.active{color:#fff;border-bottom-color:var(--accent)}
.tab-body{padding:14px 16px;display:none}.tab-body.active{display:block}
.findings{display:flex;flex-direction:column;gap:8px}
.finding{display:flex;gap:10px;align-items:flex-start;background:var(--bg3);border-radius:6px;padding:10px 12px;border-left:3px solid transparent}
.finding.high{border-left-color:var(--danger)}.finding.med{border-left-color:var(--warn)}.finding.low{border-left-color:var(--accent)}.finding.info{border-left-color:var(--border)}
.badge{font-size:9px;font-weight:600;padding:2px 7px;border-radius:3px;text-transform:uppercase;letter-spacing:0.08em;flex-shrink:0;margin-top:2px}
.badge.high{background:#3a1515;color:var(--danger)}.badge.med{background:#2e2208;color:var(--warn)}.badge.low{background:#0d1f3a;color:var(--accent)}.badge.info{background:var(--bg4);color:var(--muted)}
.fname{color:#fff;font-weight:500;font-size:12px;margin-bottom:2px}
.fdetail{color:var(--muted);font-size:11px;line-height:1.5}
.hex{font-family:var(--font);font-size:11px;color:var(--text);line-height:1.8;overflow-x:auto;white-space:pre;max-height:240px;overflow-y:auto;background:var(--bg3);border-radius:6px;padding:12px}
.entropy-wrap{display:flex;flex-direction:column;gap:5px}
.eb{display:flex;align-items:center;gap:8px}
.eb-addr{font-size:10px;color:var(--muted);width:70px;flex-shrink:0}
.eb-track{flex:1;height:7px;background:var(--bg4);border-radius:4px;overflow:hidden}
.eb-fill{height:100%;border-radius:4px}
.eb-val{font-size:10px;color:var(--text);width:36px;text-align:right}
.strs{font-family:var(--font);font-size:11px;color:var(--text);max-height:240px;overflow-y:auto;background:var(--bg3);border-radius:6px;padding:12px;line-height:1.7;white-space:pre-wrap;word-break:break-all}
.actions{display:flex;gap:10px;flex-wrap:wrap;padding:14px 16px;border-top:1px solid var(--border)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:5px;border:1px solid var(--border);background:var(--bg3);color:var(--text);cursor:pointer;font-family:var(--font);font-size:12px;transition:background .1s}
.btn:hover{background:var(--bg4);border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{opacity:.88}
.logarea{font-family:var(--font);font-size:11px;color:var(--muted);line-height:1.7;max-height:100px;overflow-y:auto;padding:10px 16px;border-top:1px solid var(--border)}
.logarea .ok{color:var(--ok)}.logarea .err{color:var(--danger)}.logarea .warn{color:var(--warn)}
.progress{height:2px;background:var(--border);margin-bottom:16px;border-radius:2px;overflow:hidden}
.progress .fill{height:100%;background:var(--accent);border-radius:2px;transition:width .3s}
.hidden{display:none}
</style>
</head>
<body>
<div class="header">
  <div class="logo">FA</div>
  <div>
    <h1>Firmware Encryption Analyser</h1>
    <div class="sub">Entropy · XOR detection · Magic bytes · String extraction · Security review tool</div>
  </div>
</div>
<div class="main">
<div class="drop" id="drop">
  <input type="file" id="fileIn">
  <div class="icon">&#128230;</div>
  <div class="lbl">Drop firmware file here</div>
  <div class="dsub">Click to browse &mdash; .bin .img .fw .hex .rom or any binary accepted</div>
</div>
<div class="progress hidden" id="prog"><div class="fill" id="progFill" style="width:0%"></div></div>
<div id="results" class="hidden">
<div class="panel">
  <div class="panel-title">Overview</div>
  <div class="metrics" id="metrics"></div>
</div>
<div class="panel">
  <div class="tabs">
    <button class="tab active" onclick="tab('findings')">Findings</button>
    <button class="tab" onclick="tab('entropy')">Entropy map</button>
    <button class="tab" onclick="tab('hex')">Hex dump</button>
    <button class="tab" onclick="tab('strings')">Strings</button>
  </div>
  <div class="tab-body active" id="tb-findings"><div class="findings" id="findings"></div></div>
  <div class="tab-body" id="tb-entropy"><div class="entropy-wrap" id="entropyWrap"></div></div>
  <div class="tab-body" id="tb-hex"><div class="hex" id="hexView"></div></div>
  <div class="tab-body" id="tb-strings"><div class="strs" id="strView"></div></div>
  <div class="actions" id="actions"></div>
  <div class="logarea" id="logArea"></div>
</div>
</div>
</div>
<script>
let state=null,currentFile=null;
const drop=document.getElementById('drop'),fileIn=document.getElementById('fileIn');
drop.addEventListener('click',()=>fileIn.click());
drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('over');});
drop.addEventListener('dragleave',()=>drop.classList.remove('over'));
drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('over');if(e.dataTransfer.files[0])go(e.dataTransfer.files[0]);});
fileIn.addEventListener('change',()=>{if(fileIn.files[0])go(fileIn.files[0]);});
function tab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',['findings','entropy','hex','strings'][i]===name));
  document.querySelectorAll('.tab-body').forEach(b=>b.classList.remove('active'));
  document.getElementById('tb-'+name).classList.add('active');
}
function log(msg,cls=''){const el=document.getElementById('logArea');el.innerHTML+='<span class="'+cls+'">'+msg+'</span>\n';el.scrollTop=el.scrollHeight;}
function prog(pct){document.getElementById('progFill').style.width=pct+'%';}
async function go(file){
  currentFile=file;
  document.getElementById('results').classList.add('hidden');
  document.getElementById('prog').classList.remove('hidden');
  document.getElementById('logArea').innerHTML='';
  prog(10);
  log('[+] Uploading '+file.name+' ('+Math.round(file.size/1024)+' KB)...');
  const fd=new FormData();fd.append('firmware',file);
  try{
    prog(30);
    const r=await fetch('/analyse',{method:'POST',body:fd});
    prog(80);
    const data=await r.json();
    prog(100);
    if(data.error){log('[!] '+data.error,'err');return;}
    state=data;render(data);
    document.getElementById('results').classList.remove('hidden');
    log('[+] Analysis complete.','ok');
  }catch(e){log('[!] Error: '+e.message,'err');}
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function render(d){
  const hc=d.globalEntropy>7.2?'danger':d.globalEntropy>6?'warn':'ok';
  document.getElementById('metrics').innerHTML=[
    {l:'File size',v:(d.fileSize/1024).toFixed(1)+' KB',c:''},
    {l:'Global entropy',v:d.globalEntropy.toFixed(2),c:hc},
    {l:'High-entropy blocks',v:d.highEntropyBlocks,c:d.highEntropyBlocks>0?'warn':''},
    {l:'Strings found',v:(d.strings||[]).length,c:''},
    {l:'Crypto strings',v:(d.cryptoStrings||[]).length,c:(d.cryptoStrings||[]).length>0?'warn':''},
    {l:'XOR candidates',v:(d.xorCandidates||[]).length,c:(d.xorCandidates||[]).length>0?'danger':''},
  ].map(m=>'<div class="metric"><div class="ml">'+m.l+'</div><div class="mv '+m.c+'">'+m.v+'</div></div>').join('');
  document.getElementById('findings').innerHTML=(d.findings||[]).map(f=>
    '<div class="finding '+f.severity+'"><span class="badge '+f.severity+'">'+f.severity+'</span><div><div class="fname">'+esc(f.name)+'</div><div class="fdetail">'+esc(f.detail)+'</div></div></div>'
  ).join('');
  document.getElementById('entropyWrap').innerHTML=(d.entropyBlocks||[]).map(b=>{
    const pct=Math.min(100,(b.entropy/8)*100).toFixed(1);
    const col=b.entropy>7.2?'#e05555':b.entropy>6?'#e0a020':'#3db87a';
    return '<div class="eb"><div class="eb-addr">0x'+b.offset.toString(16).padStart(5,'0')+'</div><div class="eb-track"><div class="eb-fill" style="width:'+pct+'%;background:'+col+'"></div></div><div class="eb-val">'+b.entropy.toFixed(2)+'</div></div>';
  }).join('');
  document.getElementById('hexView').textContent=d.hexDump||'';
  document.getElementById('strView').textContent=(d.strings||[]).join('\n')||'(no printable strings)';
  let btns='';
  if((d.xorCandidates||[]).length>0){const k=d.xorCandidates[0].key;btns+='<button class="btn primary" onclick="doDecrypt('+k+')">Decrypt XOR 0x'+k.toString(16).padStart(2,'0')+' + save</button>';}
  btns+='<button class="btn" onclick="doStrings()">Export strings</button>';
  btns+='<button class="btn" onclick="newFile()">Analyse another file</button>';
  document.getElementById('actions').innerHTML=btns;
}
async function doDecrypt(key){
  if(!currentFile)return;
  log('[+] Applying XOR 0x'+key.toString(16).padStart(2,'0')+'...');
  const fd=new FormData();fd.append('firmware',currentFile);fd.append('key',key);
  const r=await fetch('/decrypt',{method:'POST',body:fd});
  const blob=await r.blob();
  const cd=r.headers.get('Content-Disposition')||'';
  const fname=(cd.match(/filename="([^"]+)"/)|| [])[1]||'decrypted.bin';
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=fname;a.click();
  log('[+] Saved: '+fname,'ok');
}
async function doStrings(){
  if(!currentFile)return;
  const fd=new FormData();fd.append('firmware',currentFile);
  const r=await fetch('/strings',{method:'POST',body:fd});
  const blob=await r.blob();
  const cd=r.headers.get('Content-Disposition')||'';
  const fname=(cd.match(/filename="([^"]+)"/)|| [])[1]||'strings.txt';
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=fname;a.click();
  log('[+] Saved: '+fname,'ok');
}
function newFile(){currentFile=null;state=null;document.getElementById('results').classList.add('hidden');document.getElementById('prog').classList.add('hidden');document.getElementById('logArea').innerHTML='';fileIn.value='';}
</script>
</body>
</html>`

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("Cannot bind:", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := fmt.Sprintf("http://%s", addr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlPage)
	})
	mux.HandleFunc("/analyse", handleAnalyse)
	mux.HandleFunc("/decrypt", handleDecrypt)
	mux.HandleFunc("/strings", handleStrings)

	go func() {
		time.Sleep(300 * time.Millisecond)
		openBrowser(url)
	}()

	fmt.Printf("\n  Firmware Encryption Analyser\n")
	fmt.Printf("  Running at: %s\n\n", url)
	fmt.Println("  If browser does not open automatically, paste the URL above into any browser.")
	fmt.Println("  Press Ctrl+C to exit.\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}

	if runtime.GOOS == "windows" {
		fmt.Println("\nPress Enter to exit...")
		os.Stdin.Read(make([]byte, 1))
	}
}
