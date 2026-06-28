package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/folbricht/desync"
	"github.com/spf13/cobra"
)

type tarOptions struct {
	cmdStoreOptions
	chunkSize string
	desync.LocalFSOptions
	inFormat string
	desync.TarReaderOptions
}

func newTarCommand(ctx context.Context) *cobra.Command {
	var opt tarOptions

	cmd := &cobra.Command{
		Use:   "tar <index> <source>",
		Short: "Chunk a directory tree and upload to the chunk server, producing a caidx index",
		Long: `Encodes a directory tree, chunks the archive and uploads the chunks
to the configured remote chunk store, then produces a caidx index file.
Use '-' to write the index to STDOUT.

This is equivalent to first creating a catar, then chunking it into the
remote store and producing an index file, but without requiring an
intermediary catar on disk.

By default, input is read from local disk. Using --input-format=tar,
the input can be a tar file or a stream from STDIN with '-'.
		`,
		Example: `  desync tar pics.caidx $HOME/Pictures`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTar(ctx, opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.chunkSize, "chunk-size", "m", "16:64:256", "min:avg:max chunk size in kb")
	flags.StringVar(&opt.inFormat, "input-format", "disk", "input format, 'disk' or 'tar'")
	flags.BoolVarP(&opt.NoTime, "no-time", "", false, "set file timestamps to zero in the archive")
	flags.BoolVarP(&opt.AddRoot, "tar-add-root", "", false, "pretend that all tar elements have a common root directory")

	if runtime.GOOS != "windows" {
		flags.BoolVarP(&opt.OneFileSystem, "one-file-system", "x", false, "don't cross filesystem boundaries")
	}

	addStoreOptions(&opt.cmdStoreOptions, flags)
	return cmd
}

func runTar(ctx context.Context, opt tarOptions, args []string) error {
	if err := ensureDeveloperRole(ctx); err != nil {
		return err
	}
	if err := opt.cmdStoreOptions.validate(); err != nil {
		return err
	}
	if opt.AddRoot && opt.inFormat != "tar" {
		return errors.New("--tar-add-root works only with --input-format tar")
	}

	output := args[0]
	source := args[1]

	// Prepare input
	var (
		fs  desync.FilesystemReader
		err error
	)
	switch opt.inFormat {
	case "disk": // Local filesystem
		local := desync.NewLocalFS(source, opt.LocalFSOptions)
		fs = local
	case "tar": // tar archive (different formats), either file or STDOUT
		var r *os.File
		if source == "-" {
			r = os.Stdin
		} else {
			r, err = os.Open(source)
			if err != nil {
				return err
			}
			defer r.Close()
		}
		fs = desync.NewTarReader(r, opt.TarReaderOptions)
	default:
		return fmt.Errorf("invalid input format '%s'", opt.inFormat)
	}

	// Stream the output of the tar command directly into a chunker using a pipe
	r, w := io.Pipe()

	// Open the target store
	s, err := WritableStore(defaultTarUntarStoreURL, opt.cmdStoreOptions)
	if err != nil {
		return err
	}
	defer s.Close()

	// Prepare the chunker
	min, avg, max, err := parseChunkSizeParam(opt.chunkSize)
	if err != nil {
		return err
	}
	c, err := desync.NewChunker(r, min, avg, max)
	if err != nil {
		return err
	}

	// Run the tar bit in a goroutine, writing to the pipe
	var tarErr error
	go func() {
		tarErr = desync.Tar(ctx, w, fs)
		w.Close()
	}()

	// Read from the pipe, split the stream and store the chunks. This should
	// complete when Tar is done and closes the pipe writer
	index, err := desync.ChunkStream(ctx, c, s, opt.n)
	if err != nil {
		return err
	}

	index.Index.FeatureFlags |= desync.TarFeatureFlags

	// See if Tar encountered an error along the way
	if tarErr != nil {
		return tarErr
	}

	// Write the index
	return storeCaibxFile(index, output, opt.cmdStoreOptions)
}
