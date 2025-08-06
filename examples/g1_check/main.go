package main

import (
	"log"
	"time"

	"github.com/theparadigmshifters/gnark-exp/zk"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type Poseidon2Circuit struct {
	width           int
	nbFullRounds    int
	nbPartialRounds int
	roundKeys       [][]fr.Element
}

func NewPoseidon2Circuit() *Poseidon2Circuit {
	params := zk.PermutationParams()
	return &Poseidon2Circuit{
		width:           params.Width,
		nbFullRounds:    params.NbFullRounds,
		nbPartialRounds: params.NbPartialRounds,
		roundKeys:       params.RoundKeys,
	}
}

func (p *Poseidon2Circuit) sBoxCircuit(api frontend.API, x frontend.Variable) frontend.Variable {
	// S-box: x^5 = x * x^2 * x^2
	x2 := api.Mul(x, x)   // x^2
	x4 := api.Mul(x2, x2) // x^4
	return api.Mul(x4, x) // x^5
}

func (p *Poseidon2Circuit) matMulExternalCircuit(api frontend.API, input []frontend.Variable) []frontend.Variable {
	result := make([]frontend.Variable, len(input))

	if p.width == 2 {
		// For width=2: circ(2,1) matrix
		sum := api.Add(input[0], input[1])
		result[0] = api.Add(sum, input[0])
		result[1] = api.Add(sum, input[1])
	} else if p.width == 3 {
		// For width=3: circ(2,1,1) matrix
		sum := api.Add(input[0], input[1])
		sum = api.Add(sum, input[2])
		result[0] = api.Add(sum, input[0])
		result[1] = api.Add(sum, input[1])
		result[2] = api.Add(sum, input[2])
	} else {
		panic("only width=2,3 are supported")
	}

	return result
}

func (p *Poseidon2Circuit) matMulInternalCircuit(api frontend.API, input []frontend.Variable) []frontend.Variable {
	result := make([]frontend.Variable, len(input))

	if p.width == 2 {
		// Matrix [[2,1][1,3]]
		sum := api.Add(input[0], input[1])
		result[0] = api.Add(input[0], sum)
		result[1] = api.Add(api.Add(input[1], input[1]), sum) // 2*input[1] + sum
	} else if p.width == 3 {
		// Matrix [[2,1,1][1,2,1][1,1,3]]
		sum := api.Add(input[0], input[1])
		sum = api.Add(sum, input[2])
		result[0] = api.Add(input[0], sum)
		result[1] = api.Add(input[1], sum)
		result[2] = api.Add(api.Add(input[2], input[2]), sum) // 2*input[2] + sum
	} else {
		panic("only width=2,3 are supported")
	}

	return result
}

func (p *Poseidon2Circuit) addRoundKeyCircuit(api frontend.API, round int, input []frontend.Variable) {
	for i := 0; i < len(p.roundKeys[round]); i++ {
		input[i] = api.Add(input[i], p.roundKeys[round][i])
	}
}

func (p *Poseidon2Circuit) PermutationCircuit(api frontend.API, input []frontend.Variable) []frontend.Variable {
	if len(input) != p.width {
		panic("input length must match width")
	}

	state := make([]frontend.Variable, len(input))
	copy(state, input)

	state = p.matMulExternalCircuit(api, state)

	rf := p.nbFullRounds / 2

	for i := 0; i < rf; i++ {
		p.addRoundKeyCircuit(api, i, state)
		for j := 0; j < p.width; j++ {
			state[j] = p.sBoxCircuit(api, state[j])
		}
		state = p.matMulExternalCircuit(api, state)
	}

	for i := rf; i < rf+p.nbPartialRounds; i++ {
		p.addRoundKeyCircuit(api, i, state)
		state[0] = p.sBoxCircuit(api, state[0])
		state = p.matMulInternalCircuit(api, state)
	}

	for i := rf + p.nbPartialRounds; i < p.nbFullRounds+p.nbPartialRounds; i++ {
		p.addRoundKeyCircuit(api, i, state)
		for j := 0; j < p.width; j++ {
			state[j] = p.sBoxCircuit(api, state[j])
		}
		state = p.matMulExternalCircuit(api, state)
	}

	return state
}

func HashCompressCircuit(api frontend.API, x, y frontend.Variable) frontend.Variable {
	poseidon := NewPoseidon2Circuit()
	inputs := []frontend.Variable{x, y}
	result := poseidon.PermutationCircuit(api, inputs)
	return api.Add(result[1], y)
}

func HashG1Circuit(api frontend.API, xHigh, xLow, yHigh, yLow frontend.Variable) frontend.Variable {
	x := HashCompressCircuit(api, xHigh, xLow)
	y := HashCompressCircuit(api, yHigh, yLow)
	return HashCompressCircuit(api, x, y)
}

func MessageToG1Circuit(api frontend.API, msgHash []frontend.Variable) (frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) {
	// 在实际实现中，这里应该实现完整的hash-to-curve算法
	// 为了简化，我们使用一个确定性的方法来生成"伪"G1坐标

	// 使用消息哈希的组合来生成G1点的坐标分量
	xHigh := HashCompressCircuit(api, msgHash[0], msgHash[1])
	xLow := HashCompressCircuit(api, msgHash[2], msgHash[3])
	yHigh := HashCompressCircuit(api, xHigh, msgHash[0])
	yLow := HashCompressCircuit(api, xLow, msgHash[1])

	return xHigh, xLow, yHigh, yLow
}

// 测试电路
type HashTestCircuit struct {
	// G1点的分解表示（公开输入）
	XHigh frontend.Variable `gnark:",public"`
	XLow  frontend.Variable `gnark:",public"`
	YHigh frontend.Variable `gnark:",public"`
	YLow  frontend.Variable `gnark:",public"`

	// 期望的哈希结果（公开输入）
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (circuit *HashTestCircuit) Define(api frontend.API) error {
	// 在电路内部计算HashG1
	circuitHash := HashG1Circuit(api, circuit.XHigh, circuit.XLow, circuit.YHigh, circuit.YLow)

	// 验证电路内计算的结果与期望值一致
	api.AssertIsEqual(circuitHash, circuit.ExpectedHash)

	return nil
}

// MessageToG1Point 将字节消息转换为G1点
func MessageToG1Point(msg []byte) bls12381.G1Affine {
	// 使用哈希到曲线的方法
	domain := []byte("HASH_TO_G1_TEST_DOMAIN")
	point, err := bls12381.HashToG1(msg, domain)
	if err != nil {
		log.Fatalf("Failed to hash message to G1: %v", err)
	}
	return point
}

func main() {
	log.Println("开始测试时间:", time.Now())

	// 测试消息
	msg := []byte("Hello World")
	log.Printf("测试消息: %s", string(msg))

	// 步骤1: 将消息转换为G1点
	g1Point := MessageToG1Point(msg)
	log.Printf("G1点: %s", g1Point.String())

	// 步骤2: 在电路外使用HashG1计算哈希
	expectedHash := zk.HashG1(g1Point)
	log.Printf("电路外计算的哈希: %s", expectedHash.String())

	// 步骤3: 分解G1点为电路输入
	decomposed := zk.DecomposeG1(g1Point)
	xHigh := decomposed[0][0]
	xLow := decomposed[0][1]
	yHigh := decomposed[1][0]
	yLow := decomposed[1][1]

	log.Printf("分解结果:")
	log.Printf("  X高位: %s", xHigh.String())
	log.Printf("  X低位: %s", xLow.String())
	log.Printf("  Y高位: %s", yHigh.String())
	log.Printf("  Y低位: %s", yLow.String())

	// 步骤4: 编译电路
	var circuit HashTestCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("编译电路失败: %v", err)
	}
	log.Printf("电路编译成功，约束数量: %d", ccs.GetNbConstraints())

	// 步骤5: 设置证明系统
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		log.Fatalf("创建SRS失败: %v", err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		log.Fatalf("设置证明系统失败: %v", err)
	}
	log.Println("证明系统设置成功")

	// 步骤6: 创建witness
	witness := HashTestCircuit{
		XHigh:        xHigh,
		XLow:         xLow,
		YHigh:        yHigh,
		YLow:         yLow,
		ExpectedHash: expectedHash,
	}

	witnessFull, err := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatalf("创建完整witness失败: %v", err)
	}

	witnessPublic, err := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatalf("创建公开witness失败: %v", err)
	}

	// 步骤7: 生成证明
	log.Println("开始生成证明...")
	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatalf("生成证明失败: %v", err)
	}
	log.Println("证明生成成功")

	// 步骤8: 验证证明
	log.Println("开始验证证明...")
	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatalf("证明验证失败: %v", err)
	}

	log.Println("🎉 测试成功！电路内外的HashG1计算结果一致！")
	log.Println("结束测试时间:", time.Now())
}
