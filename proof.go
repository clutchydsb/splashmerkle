package splashmerkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/CryptoKass/splashmerkle/utils"
)

const MAXDEPTH = 4

type Proof struct {
	Target       []byte
	helpers      []ProofHelper
	isTargetLeft bool
}

type ProofHelper struct {
	H      []byte
	isLeaf bool
}

// Verify - veries the proof against the merkleroot
func (proof *Proof) Verify(merklerootHash []byte) bool {
	//Calculate next hash
	hash := proof.Target
	var buf [32]byte

	//calculate first hash
	fmt.Println("Testing:", hex.EncodeToString(hash), hex.EncodeToString(proof.helpers[0].H))
	if proof.isTargetLeft {
		buf := sha256.Sum256(append(hash, proof.helpers[0].H...))
		hash = buf[:32]
	} else {
		buf := sha256.Sum256(append(proof.helpers[0].H, hash...))
		hash = buf[:32]
	}

	for i := 1; i < len(proof.helpers); i++ {
		fmt.Println("Testing:", hex.EncodeToString(hash), hex.EncodeToString(proof.helpers[i].H))
		if proof.helpers[i].isLeaf {
			buf = sha256.Sum256(append(proof.helpers[i].H, hash...))
		} else {
			buf = sha256.Sum256(append(hash, proof.helpers[i].H...))
		}
		hash = buf[:]
	}

	return utils.CheckByteEq(hash, merklerootHash)
}

// GenerateProofFor will create generate the proof
// for a given target in the merkle tree.
// The proof can be used with the merkle root to
// prove the inclusion of a given target.
// TODO: improve and shortern this method
// TODO: add better notes
func (tree *Tree) GenerateProofFor(target []byte) (proof Proof, err error) {

	// Holder for left Nodes
	var leftNode *Node
	var rightNode *Node
	var buf [32]byte

	if !tree.IncludesInput(target) {
		err = errors.New("target not contained withing tree inputs")
		return
	}

	//Add target to proof
	proof.Target = target
	index := tree.GetIndex(target)
	proof.isTargetLeft = tree.Nodes[index].isLeaf

	var helper ProofHelper
	if tree.Nodes[index].GetSibling() != nil {
		sib := tree.Nodes[index].GetSibling()
		helper = ProofHelper{sib.H, sib.isLeaf}
	} else {
		helper = ProofHelper{buf[:], tree.Nodes[index].isLeaf}
	}
	proof.helpers = append(proof.helpers, helper)

	for i := 0; i < MAXDEPTH; i++ {
		isLeftLeaf := tree.Nodes[index].isLeaf
		if isLeftLeaf {
			leftNode = &tree.Nodes[index]
			rightNode = leftNode.GetSibling()
		} else {
			leftNode = tree.Nodes[index].GetSibling()
			rightNode = &tree.Nodes[index]
		}

		if rightNode != nil {
			buf = sha256.Sum256(append(leftNode.H, rightNode.H...))
		} else {
			buf = sha256.Sum256(leftNode.H)
		}

		index = tree.GetIndex(buf[:])
		if index >= len(tree.Nodes)-1 {
			fmt.Println("Proof Found", index, hex.EncodeToString(tree.Nodes[index].H))
			return
		}

		var helper ProofHelper
		if tree.Nodes[index].GetSibling() != nil {
			sib := tree.Nodes[index].GetSibling()
			helper = ProofHelper{sib.H, sib.isLeaf}
		} else {
			helper = ProofHelper{buf[:], tree.Nodes[index].isLeaf}
		}
		proof.helpers = append(proof.helpers, helper)
	}

	return
}

// GetIndex returns the index of a given target in
// the tree, GetIndex will return 0 if target is not
// in the tree.
func (tree *Tree) GetIndex(target []byte) int {
	index := 0
	for i := 0; i < len(tree.Nodes); i++ {
		if utils.CheckByteEq(tree.Nodes[i].H, target) {
			index = i
			break
		}
	}
	return index
}
