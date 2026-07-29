package main

import (
	"fmt"
	"yaxelb/internal/bpf"

	"github.com/spf13/cobra"
)

// mapsCmd represents the maps command
var mapsCmd = &cobra.Command{
	Use:   "maps",
	Short: "Dump eBPF maps of yaxelb",
	Long:  "Dump eBPF maps of yaxelb. Currently only conntrack map is implemented",
	RunE: func(cmd *cobra.Command, args []string) error {
		objs, _, err := bpf.LoadObjects()
		if err != nil {
			return err
		}
		defer objs.Close()
		iter, err := bpf.ConntrackIter(objs.Conntrack)
		if err != nil {
			return err
		}
		fmt.Println("ENTRY => 5 TUPLE")
		for tuple, entry := range iter {
			fmt.Printf("%+v => %+v\n", entry, tuple)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mapsCmd)
}
