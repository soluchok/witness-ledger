package main

import (
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/spf13/cobra"

	"github.com/soluchok/witness-ledger/cmd/witness-ledger/startcmd"
)

var logger = log.New("witness-ledger")

// This is an application which starts witness-ledger service.
func main() {
	rootCmd := &cobra.Command{
		Use: "witness-ledger",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	startCmd, err := startcmd.Cmd(&startcmd.HTTPServer{})
	if err != nil {
		logger.Fatalf(err.Error())
	}

	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("failed to run witness-ledger: %v", err)
	}
}
