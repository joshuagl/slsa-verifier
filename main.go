package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/slsa-framework/slsa-verifier/pkg"
)

var (
	provenancePath string
	artifactPath   string
	source         string
	branch         string
	tag            string
	versiontag     string
	printProv      bool
	skipVerify     bool
)

var defaultRekorAddr = "https://rekor.sigstore.dev"

func verify(ctx context.Context,
	env *dsse.Envelope, artifactHash, source, branch string,
	tag, versiontag *string,
) error {
	rClient, err := rekor.NewClient(defaultRekorAddr)
	if err != nil {
		return err
	}

	// Get Rekor entries corresponding to the binary artifact in the provenance.
	uuids, err := pkg.GetRekorEntries(rClient, artifactHash)
	if err != nil {
		return err
	}

	// Verify the provenance and return the signing certificate.
	cert, err := pkg.FindSigningCertificate(ctx, uuids, *env, rClient)
	if err != nil {
		return err
	}

	// Get the workflow info given the certificate information.
	workflowInfo, err := pkg.GetWorkflowInfoFromCertificate(cert)
	if err != nil {
		return err
	}

	// Unpack and verify info in the provenance, including the Subject Digest.
	if err := pkg.VerifyProvenance(env, artifactHash); err != nil {
		return err
	}

	// Verify the workflow identity.
	if err := pkg.VerifyWorkflowIdentity(workflowInfo, source); err != nil {
		return err
	}

	// Verify the branch.
	if err := pkg.VerifyBranch(env, branch); err != nil {
		return err
	}

	// Verify the tag.
	if tag != nil {
		if err := pkg.VerifyTag(env, *tag); err != nil {
			return err
		}
	}

	// Verify the versioned tag.
	if versiontag != nil {
		if err := pkg.VerifyVersionedTag(env, *versiontag); err != nil {
			return err
		}
	}

	b, err := json.MarshalIndent(workflowInfo, "", "\t")
	if err != nil {
		return err
	}

	fmt.Printf("verified SLSA provenance produced at \n %s\n", b)
	return nil
}

func main() {
	flag.StringVar(&provenancePath, "provenance", "", "path to a provenance file")
	flag.StringVar(&artifactPath, "artifact-path", "", "path to an artifact to verify")
	flag.StringVar(&source, "source", "", "expected source repository that should have produced the binary, e.g. github.com/some/repo")
	flag.StringVar(&branch, "branch", "main", "expected branch the binary was compiled from")
	flag.StringVar(&tag, "tag", "", "[optional] expected tag the binary was compiled from")
	flag.StringVar(&versiontag, "versioned-tag", "", "[optional] expected version the binary was compiled from. Uses semantic version to match the tag")
	flag.BoolVar(&printProv, "print-prov", false, "[optional] print the provenance predicate as unmarshalled JSON")
	flag.BoolVar(&skipVerify, "skip-verify", false, "[optional] skip verification, must be used in conjunction with 'print-prov' option")
	flag.Parse()

	if (skipVerify && !printProv) || // can only skip verification if printing provenance
		// may supply only 'provenance' when skipping verify and printing provenance
		(skipVerify && printProv && provenancePath == "") ||
		(!skipVerify && (provenancePath == "" || artifactPath == "" || source == "")) {
		flag.Usage()
		os.Exit(1)
	}

	var ptag, pversiontag *string

	if isFlagPassed("tag") {
		ptag = &tag
	}
	if isFlagPassed("versioned-tag") {
		pversiontag = &versiontag
	}

	if pversiontag != nil && ptag != nil {
		fmt.Fprintf(os.Stderr, "'version' and 'tag' options cannot be used together\n")
		os.Exit(1)
	}

	provenance, err := os.ReadFile(provenancePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read provenance %s\n", provenancePath)
		os.Exit(1)
	}

	envelope, err := pkg.EnvelopeFromBytes(provenance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode provenance %s\n", provenancePath)
		os.Exit(1)
	}

	if printProv {
		pkg.PrintProvenance(envelope)
		if skipVerify {
			return
		}
	}

	if err := runVerify(artifactPath, envelope, source, branch,
		ptag, pversiontag); err != nil {
		fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("successfully verified SLSA provenance")
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func runVerify(artifactPath string, envelope *dsse.Envelope, source, branch string,
	ptag, pversiontag *string,
) error {
	f, err := os.Open(artifactPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	return verify(ctx, envelope,
		hex.EncodeToString(h.Sum(nil)),
		source, branch,
		ptag, pversiontag)
}
