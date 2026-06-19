package main

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pathfinder/internal/archive"
	"github.com/pathfinder/internal/config"
	"github.com/pathfinder/internal/modules"
	"github.com/pathfinder/internal/output"
)

func finalizeArchive(ctx *modules.ModuleContext, cfg *config.Config, host HostMeta,
	start time.Time, archiveSkipped []string, zipPath string,
	zw *zip.Writer, zipFile *os.File, baseParent string) (archiveSound bool, manifestPath string) {

	// Flush remaining flat files (Report.md, commands.log, findings JSON) into zip.
	finalSkips, flushErr := archive.FlushDirToZip(zw, ctx.Dirs.Base, baseParent)
	archiveSkipped = append(archiveSkipped, finalSkips...)
	if flushErr != nil {
		output.Warn(fmt.Sprintf("archive flush error: %v", flushErr))
	}
	closeErr := zw.Close()
	if closeErr != nil {
		output.Warn(fmt.Sprintf("zip close error: %v", closeErr))
	}
	closeFileErr := zipFile.Close()
	if closeFileErr != nil {
		output.Warn(fmt.Sprintf("zip file close error: %v", closeFileErr))
	}

	// Do not delete the source until we are sure the archive is sound. A
	// truncated archive (disk full, interrupted write) must never become the
	// sole evidence copy with a manifest that certifies its hash.
	archiveSound = closeErr == nil && closeFileErr == nil
	if archiveSound {
		if count, vErr := archive.VerifyZip(zipPath); vErr != nil || count == 0 {
			archiveSound = false
			if vErr != nil {
				output.Warn(fmt.Sprintf("archive verification failed: %v", vErr))
			} else {
				output.Warn("archive verification failed: zip has no entries")
			}
		}
	}

	var md5sum, sha256sum string
	if hashMD5, hashSHA, hashErr := archive.FileHashes(zipPath); hashErr != nil {
		output.Warn(fmt.Sprintf("archive hash error: %v", hashErr))
		archiveSound = false
	} else {
		md5sum, sha256sum = hashMD5, hashSHA
	}

	if !archiveSound {
		output.Warn("Archive is unverified or corrupt — source directory preserved for recovery")
		output.Note(fmt.Sprintf("Output directory preserved at: %s", ctx.Dirs.Base))
	} else if removeErr := os.RemoveAll(ctx.Dirs.Base); removeErr != nil {
		output.Warn(fmt.Sprintf("cleanup error: %v", removeErr))
		output.Note(fmt.Sprintf("Output directory preserved at: %s", ctx.Dirs.Base))
	} else {
		output.Ok(fmt.Sprintf("Archive created: %s", zipPath))
		output.Ok(fmt.Sprintf("Directory removed: %s", ctx.Dirs.Base))
	}

	var mainSize, sseSize int64
	if fi, statErr := os.Stat(zipPath); statErr == nil {
		mainSize = fi.Size()
	}
	if ctx.SSEZipPath != "" {
		if fi, statErr := os.Stat(ctx.SSEZipPath); statErr == nil {
			sseSize = fi.Size()
		}
	}

	manifestPath = strings.TrimSuffix(zipPath, ".zip") + "-manifest.txt"
	mp := archive.ManifestParams{
		CaseID:         cfg.CaseID,
		Examiner:       host.Operator,
		Hostname:       host.Hostname,
		OS:             host.OS,
		Kernel:         host.Kernel,
		Arch:           host.Arch,
		CPU:            host.CPU,
		Memory:         host.MemTotal,
		Timezone:       host.TimeZone,
		IPs:            host.IPs,
		Mounts:         host.Mounts,
		StartTime:      start,
		EndTime:        time.Now().UTC(),
		Mode:           cfg.Mode,
		ManifestPath:   cfg.ManifestPath,
		IOCFile:        cfg.IOCFile,
		SuppressFile:   cfg.SuppressFile,
		Stealth:        cfg.Stealth,
		Artifacts:      ctx.SSEArtifacts,
		Collected:      ctx.SSECollected,
		Skipped:        ctx.SSESkipped,
		MainZipPath:    zipPath,
		MainZipSize:    mainSize,
		MainZipMD5:     md5sum,
		MainZipSHA256:  sha256sum,
		SSEZipPath:     ctx.SSEZipPath,
		SSEZipSize:     sseSize,
		SSEZipSHA256:   ctx.SSEZipSHA256,
		ArchiveSkipped: archiveSkipped,
	}
	if err := archive.WriteManifest(manifestPath, mp); err != nil {
		output.Warn(fmt.Sprintf("manifest write error: %v", err))
	}

	if ctx.Uploader != nil && archiveSound {
		ctx.Uploader.Upload(manifestPath) // small artifact first: carries expected hashes
		ctx.Uploader.Upload(zipPath)
		if upErr := ctx.Uploader.Wait(); upErr != nil {
			output.Warn(fmt.Sprintf("Azure upload failed → case %s: %v", cfg.CaseID, upErr))
		} else {
			output.Ok(fmt.Sprintf("Azure upload complete → case %s", cfg.CaseID))
		}
	} else if ctx.Uploader != nil {
		output.Warn("Azure upload skipped: archive is unverified or corrupt (source dir preserved)")
	}

	return archiveSound, manifestPath
}
