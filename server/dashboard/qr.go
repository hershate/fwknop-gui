// qr.go — 最小 QR 编码器：字节模式、纠错等级 M、版本 1–40 自动、掩码按
// 罚分自动选择。仅依赖标准库，供「签发/重发 URI」把 fwknop:// 授权渲染为
// 可扫描的 SVG 二维码（客户端 fwknop import 支持 QR 图片导入）。
//
// 容量/块结构/定位坐标表见 qr_tables.go（ISO/IEC 18004，经 libqrencode
// qrspec.c 机械转写并校验）；编码正确性由 GnomeQR 参考实现差分比对保证。
package main

import (
	"errors"
	"fmt"
	"strings"
)

/* ---------- GF(2^8) Reed-Solomon（本原多项式 0x11D） ---------- */

var qrGFExp, qrGFLog = func() ([512]byte, [256]byte) {
	var exp [512]byte
	var log [256]byte
	x := 1
	for i := 0; i < 255; i++ {
		exp[i] = byte(x)
		log[x] = byte(i)
		x <<= 1
		if x >= 0x100 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	return exp, log
}()

func qrGFMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return qrGFExp[int(qrGFLog[a])+int(qrGFLog[b])]
}

// qrRSGenerator 返回 degree 阶生成多项式系数（降次排列，不含最高次项；
// 与移位寄存器余式计算的方向约定一致——升次排列会得到逐位反转的错误余式）。
func qrRSGenerator(degree int) []byte {
	gen := make([]byte, degree)
	gen[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := 0; j < degree; j++ {
			gen[j] = qrGFMul(gen[j], root)
			if j+1 < degree {
				gen[j] ^= gen[j+1]
			}
		}
		root = qrGFMul(root, 2)
	}
	return gen
}

// qrRSRemainder 计算 data 除以生成多项式的余式（degree 个纠错码）。
func qrRSRemainder(data, gen []byte) []byte {
	rem := make([]byte, len(gen))
	for _, d := range data {
		factor := d ^ rem[0]
		copy(rem, rem[1:])
		rem[len(rem)-1] = 0
		for i, g := range gen {
			rem[i] ^= qrGFMul(g, factor)
		}
	}
	return rem
}

/* ---------- 位流 ---------- */

type qrBitBuf struct {
	bits []bool
}

func (b *qrBitBuf) put(val, n int) {
	for i := n - 1; i >= 0; i-- {
		b.bits = append(b.bits, (val>>i)&1 != 0)
	}
}

/* ---------- 编码 ---------- */

// qrEncode 把 text 编码为 QR 矩阵（返回 [y][x]，true=深色模块）。
// 仅字节模式 + 纠错 M——fwknop:// URI 必含小写字母与符号，其他模式无益。
func qrEncode(text string) ([][]bool, error) {
	data := []byte(text)
	if len(data) == 0 {
		return nil, errors.New("空内容")
	}
	// 选最小可容纳版本：4 位模式 + 计数位(v<10:8 否则 16) + 数据位
	version := -1
	for v := 1; v <= 40; v++ {
		ccBits := 8
		if v >= 10 {
			ccBits = 16
		}
		if 4+ccBits+len(data)*8 <= qrDataCodewords(v)*8 {
			version = v
			break
		}
	}
	if version < 0 {
		return nil, fmt.Errorf("内容过长（%d 字节），超出 QR 容量", len(data))
	}

	// 数据位流：模式 0100 + 计数 + 数据 + 终止符 + 对齐 + 填充字节
	var buf qrBitBuf
	buf.put(0x4, 4)
	if version >= 10 {
		buf.put(len(data), 16)
	} else {
		buf.put(len(data), 8)
	}
	for _, c := range data {
		buf.put(int(c), 8)
	}
	dataCw := qrDataCodewords(version)
	capBits := dataCw * 8
	if rem := capBits - len(buf.bits); rem > 0 {
		buf.put(0, min(4, rem))
	}
	for len(buf.bits)%8 != 0 {
		buf.put(0, 1)
	}
	for pad := 0xEC; len(buf.bits) < capBits; pad ^= 0xEC ^ 0x11 {
		buf.put(pad, 8)
	}
	codewords := make([]byte, dataCw)
	for i := range codewords {
		for j := 0; j < 8; j++ {
			if buf.bits[i*8+j] {
				codewords[i] |= 1 << (7 - j)
			}
		}
	}

	// RS 分块 + 交错
	b1, b2 := qrBlocksM[version][0], qrBlocksM[version][1]
	k := dataCw / (b1 + b2)
	eccPerBlock := qrCap[version][1] / (b1 + b2)
	gen := qrRSGenerator(eccPerBlock)
	type block struct{ data, ecc []byte }
	blocks := make([]block, 0, b1+b2)
	off := 0
	for i := 0; i < b1+b2; i++ {
		n := k
		if i >= b1 {
			n = k + 1
		}
		d := codewords[off : off+n]
		off += n
		blocks = append(blocks, block{d, qrRSRemainder(d, gen)})
	}
	var all []byte
	for i := 0; i <= k; i++ {
		for _, b := range blocks {
			if i < len(b.data) {
				all = append(all, b.data[i])
			}
		}
	}
	for i := 0; i < eccPerBlock; i++ {
		for _, b := range blocks {
			all = append(all, b.ecc[i])
		}
	}

	return qrDrawMatrix(version, all), nil
}

func qrDataCodewords(version int) int {
	return qrCap[version][0] - qrCap[version][1]
}

/* ---------- 矩阵绘制 ---------- */

func qrDrawMatrix(version int, codewords []byte) [][]bool {
	size := version*4 + 17
	mod := make([][]bool, size)   // 模块值
	fn := make([][]bool, size)    // 功能图形占位（数据/掩码不得触碰）
	for i := range mod {
		mod[i] = make([]bool, size)
		fn[i] = make([]bool, size)
	}
	setFn := func(x, y int, dark bool) {
		if x >= 0 && x < size && y >= 0 && y < size {
			mod[y][x] = dark
			fn[y][x] = true
		}
	}
	// 寻像图形 + 分隔符（三角）
	finder := func(cx, cy int) {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				d := max(abs(dx), abs(dy))
				setFn(cx+dx, cy+dy, d != 2 && d != 4)
			}
		}
	}
	finder(3, 3)
	finder(size-4, 3)
	finder(3, size-4)
	// 校正图形
	if pos := qrAlignPos(version); len(pos) > 0 {
		for i, cx := range pos {
			for j, cy := range pos {
				// 与寻像重叠的三角不画
				if (i == 0 && j == 0) || (i == 0 && j == len(pos)-1) || (i == len(pos)-1 && j == 0) {
					continue
				}
				for dy := -2; dy <= 2; dy++ {
					for dx := -2; dx <= 2; dx++ {
						setFn(cx+dx, cy+dy, max(abs(dx), abs(dy)) != 1)
					}
				}
			}
		}
	}
	// 时序图形
	for i := 0; i < size; i++ {
		if !fn[6][i] {
			setFn(i, 6, i%2 == 0)
		}
		if !fn[i][6] {
			setFn(6, i, i%2 == 0)
		}
	}
	// 格式信息占位（掩码确定后回填）+ 暗模块
	for i := 0; i <= 8; i++ {
		if i != 6 {
			fn[8][i] = true
			fn[i][8] = true
		}
	}
	for i := 0; i < 8; i++ {
		fn[8][size-1-i] = true
		fn[size-1-i][8] = true
	}
	mod[size-8][8] = true // 暗模块
	fn[size-8][8] = true
	// 版本信息（v≥7）
	if version >= 7 {
		rem := qrPolyMod(version<<12, 0x1F25)
		bits := version<<12 | rem
		for i := 0; i < 18; i++ {
			b := (bits>>i)&1 != 0
			setFn(size-11+i%3, i/3, b)
			setFn(i/3, size-11+i%3, b)
		}
	}

	// 数据位 zigzag 填充
	bitIdx, upward := 0, true
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			y := vert
			if upward {
				y = size - 1 - vert
			}
			for j := 0; j < 2; j++ {
				x := right - j
				if !fn[y][x] && bitIdx < len(codewords)*8 {
					mod[y][x] = (codewords[bitIdx>>3]>>(7-bitIdx&7))&1 != 0
					bitIdx++
				}
			}
		}
		upward = !upward
	}

	// 掩码：8 选 1（罚分最低）
	bestMask, bestPenalty := -1, int(^uint(0)>>1)
	var best [][]bool
	for mask := 0; mask < 8; mask++ {
		m := qrClone(mod)
		qrApplyMask(m, fn, mask)
		qrDrawFormatBits(m, mask)
		if p := qrPenalty(m); p < bestPenalty {
			bestMask, bestPenalty, best = mask, p, m
		}
	}
	_ = bestMask
	return best
}

// qrAlignPos 计算校正图形中心坐标（含 6；v1 为空）。
func qrAlignPos(version int) []int {
	if version == 1 {
		return nil
	}
	ap := qrAlign[version]
	width := version*4 + 17
	d := ap[1] - ap[0]
	w := 2
	if d >= 0 {
		w = (width-ap[0])/d + 2
	}
	pos := []int{6}
	cx := ap[0]
	for i := 0; i < w-1; i++ {
		pos = append(pos, cx)
		cx += d
	}
	return pos
}

func qrMaskBit(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return (x*y)%2+(x*y)%3 == 0
	case 6:
		return ((x*y)%2+(x*y)%3)%2 == 0
	default: // 7
		return ((x+y)%2+(x*y)%3)%2 == 0
	}
}

func qrApplyMask(mod, fn [][]bool, mask int) {
	size := len(mod)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if !fn[y][x] && qrMaskBit(mask, x, y) {
				mod[y][x] = !mod[y][x]
			}
		}
	}
}

// qrDrawFormatBits 写入 15 位 BCH 格式信息（纠错 M=00 + 掩码 3 位）。
func qrDrawFormatBits(mod [][]bool, mask int) {
	size := len(mod)
	data := mask // M 级 ecl 位为 00，(00<<3)|mask
	rem := qrPolyMod(data<<10, 0x537)
	bits := (data<<10 | rem) ^ 0x5412
	get := func(i int) bool { return (bits>>i)&1 != 0 }
	for i := 0; i <= 5; i++ {
		mod[i][8] = get(i)
	}
	mod[7][8] = get(6)
	mod[8][8] = get(7)
	mod[8][7] = get(8)
	for i := 9; i < 15; i++ {
		mod[8][14-i] = get(i)
	}
	for i := 0; i < 8; i++ {
		mod[8][size-1-i] = get(i)
	}
	for i := 8; i < 15; i++ {
		mod[size-15+i][8] = get(i)
	}
	mod[size-8][8] = true
}

// qrPolyMod 计算 x^deg(data) mod poly（poly 最高次幂由位数隐含）。
func qrPolyMod(data, poly int) int {
	for i := 31; i >= 0; i-- {
		if (data>>i)&1 != 0 && i >= polyDeg(poly) {
			data ^= poly << (i - polyDeg(poly))
		}
	}
	return data
}

func polyDeg(p int) int {
	d := 0
	for p > 1 {
		p >>= 1
		d++
	}
	return d
}

/* ---------- 罚分（ISO/IEC 18004 §8.8.2） ---------- */

func qrPenalty(m [][]bool) int {
	size := len(m)
	score := 0
	// N1：行/列 ≥5 同色连排
	for y := 0; y < size; y++ {
		score += qrPenaltyRun(m[y])
	}
	for x := 0; x < size; x++ {
		col := make([]bool, size)
		for y := 0; y < size; y++ {
			col[y] = m[y][x]
		}
		score += qrPenaltyRun(col)
	}
	// N2：2×2 同色块
	for y := 0; y < size-1; y++ {
		for x := 0; x < size-1; x++ {
			c := m[y][x]
			if m[y][x+1] == c && m[y+1][x] == c && m[y+1][x+1] == c {
				score += 3
			}
		}
	}
	// N3：类寻像图案（1011101 且任一侧带 4 连浅色）
	pat := []bool{true, false, true, true, true, false, true}
	for y := 0; y < size; y++ {
		score += qrPenaltyFinder(m[y], pat)
	}
	for x := 0; x < size; x++ {
		col := make([]bool, size)
		for y := 0; y < size; y++ {
			col[y] = m[y][x]
		}
		score += qrPenaltyFinder(col, pat)
	}
	// N4：深色占比偏离 50%
	dark := 0
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if m[y][x] {
				dark++
			}
		}
	}
	total := size * size
	k := abs(dark*20-total*10) / total
	score += k * 10
	return score
}

func qrPenaltyRun(line []bool) int {
	score, run := 0, 1
	for i := 1; i <= len(line); i++ {
		if i < len(line) && line[i] == line[i-1] {
			run++
		} else {
			if run >= 5 {
				score += 3 + run - 5
			}
			run = 1
		}
	}
	return score
}

func qrPenaltyFinder(line, pat []bool) int {
	score := 0
	n := len(pat)
	for i := 0; i+n <= len(line); i++ {
		match := true
		for j := 0; j < n; j++ {
			if line[i+j] != pat[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		// 前 4 连浅 或 后 4 连浅
		if i >= 4 {
			ok := true
			for j := i - 4; j < i; j++ {
				if line[j] {
					ok = false
					break
				}
			}
			if ok {
				score += 40
				continue
			}
		}
		if i+n+4 <= len(line) {
			ok := true
			for j := i + n; j < i+n+4; j++ {
				if line[j] {
					ok = false
					break
				}
			}
			if ok {
				score += 40
			}
		}
	}
	return score
}

/* ---------- SVG 输出 ---------- */

// qrSVG 把矩阵渲染为内联 SVG（4 模块静区；深色模块合并为单行游程路径）。
func qrSVG(mod [][]bool) string {
	size := len(mod)
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, size+8, size+8)
	sb.WriteString(`<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < size; y++ {
		x := 0
		for x < size {
			if mod[y][x] {
				x0 := x
				for x < size && mod[y][x] {
					x++
				}
				fmt.Fprintf(&sb, "M%d %dh%dv1h-%dz", x0+4, y+4, x-x0, x-x0)
			} else {
				x++
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String()
}

func qrClone(m [][]bool) [][]bool {
	out := make([][]bool, len(m))
	for i, row := range m {
		out[i] = append([]bool(nil), row...)
	}
	return out
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
