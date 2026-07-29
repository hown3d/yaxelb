package bpf

import (
	"iter"

	"github.com/cilium/ebpf"
)

func ConntrackIter(m *ebpf.Map) (iter.Seq2[LBFiveTuple, LBConntrackEntry], error) {
	iter := m.Iterate()
	return func(yield func(LBFiveTuple, LBConntrackEntry) bool) {
		var (
			tuple lbFiveTupleT
			entry lbConntrackEntry
		)
		for iter.Next(&tuple, &entry) {
			if !yield(lbFiveTupleFromBpf(tuple), lbConntrackEntryFromBpf(entry)) {
				return
			}
		}

		if err := iter.Err(); err != nil {
			// TODO: handle error
			panic(err)
		}
	}, nil
}

func ConntrackV6Iter(m *ebpf.Map) (iter.Seq2[LBFiveTuple, LBConntrackEntry], error) {
	iter := m.Iterate()
	return func(yield func(LBFiveTuple, LBConntrackEntry) bool) {
		var (
			tuple lbV6FiveTupleT
			entry lbV6ConntrackEntry
		)
		for iter.Next(&tuple, &entry) {
			if !yield(lbV6FiveTupleFromBpf(tuple), lbV6ConntrackEntryFromBpf(entry)) {
				return
			}
		}

		if err := iter.Err(); err != nil {
			// TODO: handle error
			panic(err)
		}
	}, nil
}
