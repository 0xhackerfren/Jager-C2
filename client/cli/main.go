package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	serverAddr string
	certFile   string
	keyFile    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "jager",
		Short: "Jager-C2 Operator CLI",
		Long:  "Command-line interface for Jager-C2 teamserver operations",
	}

	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "http://127.0.0.1:31338", "Teamserver REST management URL")
	rootCmd.PersistentFlags().StringVar(&certFile, "cert", "", "Operator certificate file")
	rootCmd.PersistentFlags().StringVar(&keyFile, "key", "", "Operator key file")

	rootCmd.AddCommand(
		sessionsCmd(),
		listenersCmd(),
		buildCmd(),
		taskCmd(),
		campaignCmd(),
		credsCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func sessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Manage implant sessions",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List active sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listSessions()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "interact [session-id]",
		Short: "Interact with a session (REPL)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return interactSession(args[0])
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "kill [session-id]",
		Short: "Terminate a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return killSession(args[0])
		},
	})

	return cmd
}

func listenersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listeners",
		Short: "Manage C2 listeners",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List active listeners",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Active Listeners:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tName\tTransport\tAddress\tStatus")
			fmt.Fprintln(w, "--\t----\t---------\t-------\t------")
			w.Flush()
			return nil
		},
	})

	var (
		lName      string
		lTransport string
		lHost      string
		lPort      int
	)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new listener",
		RunE: func(cmd *cobra.Command, args []string) error {
			return createListener(lName, lTransport, lHost, lPort)
		},
	}
	createCmd.Flags().StringVar(&lName, "name", "", "Listener name")
	createCmd.Flags().StringVar(&lTransport, "transport", "https", "Transport type (https, dns, smb, tcp)")
	createCmd.Flags().StringVar(&lHost, "host", "0.0.0.0", "Bind address")
	createCmd.Flags().IntVar(&lPort, "port", 443, "Bind port")
	cmd.AddCommand(createCmd)

	return cmd
}

func buildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Generate implants and payloads",
	}

	var (
		bListener string
		bOS       string
		bArch     string
		bFormat   string
		bProfile  string
		bOutput   string
	)

	implantCmd := &cobra.Command{
		Use:   "implant",
		Short: "Generate a new implant",
		RunE: func(cmd *cobra.Command, args []string) error {
			return buildImplant(bListener, bOS, bArch, bFormat, bProfile, bOutput)
		},
	}
	implantCmd.Flags().StringVar(&bListener, "listener", "", "Target listener ID")
	implantCmd.Flags().StringVar(&bOS, "os", "windows", "Target OS")
	implantCmd.Flags().StringVar(&bArch, "arch", "x64", "Target architecture")
	implantCmd.Flags().StringVar(&bFormat, "format", "exe", "Output format")
	implantCmd.Flags().StringVar(&bProfile, "profile", "default", "IOC profile")
	implantCmd.Flags().StringVar(&bOutput, "output", "", "Output file path")
	cmd.AddCommand(implantCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List previous builds",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Previous Builds:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tFormat\tOS/Arch\tProfile\tCreated")
			fmt.Fprintln(w, "--\t------\t-------\t-------\t-------")
			w.Flush()
			return nil
		},
	})

	return cmd
}

func taskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "task",
		Short: "Task sessions with commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "shell [session-id] [command...]",
		Short: "Execute a shell command",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			command := strings.Join(args[1:], " ")
			fmt.Printf("Tasking %s: shell %s\n", sessionID, command)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "upload [session-id] [local-path] [remote-path]",
		Short: "Upload a file",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Uploading %s to %s on session %s\n", args[1], args[2], args[0])
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "download [session-id] [remote-path]",
		Short: "Download a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Downloading %s from session %s\n", args[1], args[0])
			return nil
		},
	})

	return cmd
}

func campaignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "campaign",
		Short: "Manage campaigns",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List campaigns",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Campaigns:")
			return nil
		},
	})

	return cmd
}

func credsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "creds",
		Short: "Credential vault operations",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Stored Credentials:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tDomain\\User\tType\tSource\tCracked")
			fmt.Fprintln(w, "--\t-----------\t----\t------\t-------")
			w.Flush()
			return nil
		},
	})

	return cmd
}

