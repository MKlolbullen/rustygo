// cmd/scripts.go
package cmd

import (
    "context"
    "fmt"
    "time"

    "github.com/spf13/cobra"
    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/scripts"
)

func NewScriptsCommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "scripts",
        Short: "List and run configured scripts",
    }

    cmd.AddCommand(
        &cobra.Command{
            Use:   "list",
            Short: "List scripts",
            RunE: func(cmd *cobra.Command, args []string) error {
                cfg, err := config.Load()
                if err != nil {
                    return err
                }
                r := scripts.NewRunner(cfg)
                for _, s := range r.List() {
                    fmt.Printf("%-20s  %s\n", s.Name, s.Description)
                }
                return nil
            },
        },
        &cobra.Command{
            Use:   "run <name> [args...]",
            Short: "Run a script",
            Args:  cobra.MinimumNArgs(1),
            RunE: func(cmd *cobra.Command, args []string) error {
                cfg, err := config.Load()
                if err != nil {
                    return err
                }
                r := scripts.NewRunner(cfg)
                name := args[0]
                extra := []string{}
                if len(args) > 1 {
                    extra = args[1:]
                }
                ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
                defer cancel()
                res, err := r.Run(ctx, name, extra)
                if err != nil {
                    fmt.Printf("Error: %v\n", err)
                }
                if res != nil {
                    fmt.Printf("Exit code: %d\n\n", res.ExitCode)
                    fmt.Print(res.Stdout)
                }
                return nil
            },
        },
    )

    return cmd
}
