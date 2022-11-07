package soci

import (
	"fmt"
	"io"
	"os"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
)

type IndexBuilder struct {
	contentStore        content.Store
	spanSize            int64
	minLayerSize        int64
	buildToolIdentifier string
}

func NewIndexBuilder(contentStore content.Store) *IndexBuilder {
	defaultSpanSize := int64(1 << 22)
	return &IndexBuilder{
		contentStore:        contentStore,
		spanSize:            defaultSpanSize,
		minLayerSize:        0,
		buildToolIdentifier: "AWS SOCI CLI v0.1",
	}
}

func (b *IndexBuilder) WithSpanSize(spanSize int64) *IndexBuilder {
	b.spanSize = spanSize
	return b
}

func (b *IndexBuilder) WithMinLayerSize(minLayerSize int64) *IndexBuilder {
	b.minLayerSize = minLayerSize
	return b
}

func (b *IndexBuilder) WithBuildToolIdentifer(buildToolIdentifier string) *IndexBuilder {
	b.buildToolIdentifier = buildToolIdentifier
	return b
}

// BuildIndex builds SOCI index for an image
// This returns SOCI index manifest and an array of io.Reader of zTOCs
func (b *IndexBuilder) BuildIndex(ctx context.Context, desc ocispec.Descriptor) (Index, []io.Reader, error) {
	platform := platforms.Default()
	// we get manifest descriptor before calling images.Manifest, since after calling
	// images.Manifest, images.Children will error out when reading the manifest blob (this happens on containerd side)
	imgManifestDesc, err := GetImageManifestDescriptor(ctx, b.contentStore, desc, platform)
	if err != nil {
		return Index{}, nil, err
	}
	imageManifest, err := images.Manifest(ctx, b.contentStore, desc, platform)
	if err != nil {
		return Index{}, nil, err
	}

	sociLayersDesc := make([]*ocispec.Descriptor, len(imageManifest.Layers))
	ztocReaders := make([]io.Reader, len(imageManifest.Layers))
	eg, ctx := errgroup.WithContext(ctx)
	for i, l := range imageManifest.Layers {
		i, l := i, l
		eg.Go(func() error {
			ztocReader, desc, err := b.buildSociLayer(ctx, l, b.spanSize)
			if err != nil {
				return fmt.Errorf("could not build zTOC for %s: %w", l.Digest.String(), err)
			}
			sociLayersDesc[i] = desc
			ztocReaders[i] = ztocReader
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return Index{}, nil, err
	}

	ztocsDesc := make([]ocispec.Descriptor, 0, len(imageManifest.Layers))
	for _, desc := range sociLayersDesc {
		if desc != nil {
			ztocsDesc = append(ztocsDesc, *desc)
		}
	}

	annotations := map[string]string{
		IndexAnnotationBuildToolIdentifier: b.buildToolIdentifier,
	}

	refers := &ocispec.Descriptor{
		MediaType:   imgManifestDesc.MediaType,
		Digest:      imgManifestDesc.Digest,
		Size:        imgManifestDesc.Size,
		Annotations: imgManifestDesc.Annotations,
	}
	return *newOCIArtifactManifest(ztocsDesc, refers, annotations), ztocReaders, nil
}

// buildSociLayer builds the ztoc for an image layer and returns a Descriptor for the new ztoc.
func (b *IndexBuilder) buildSociLayer(ctx context.Context, desc ocispec.Descriptor, spanSize int64) (io.Reader, *ocispec.Descriptor, error) {
	if !images.IsLayerType(desc.MediaType) {
		return nil, nil, errNotLayerType
	}
	// check if we need to skip building the zTOC
	if desc.Size < b.minLayerSize {
		fmt.Printf("layer %s -> ztoc skipped\n", desc.Digest)
		return nil, nil, nil
	}
	compression, err := images.DiffCompression(ctx, desc.MediaType)
	if err != nil {
		return nil, nil, fmt.Errorf("could not determine layer compression: %w", err)
	}
	if compression != "gzip" {
		return nil, nil, fmt.Errorf("layer %s (%s) must be compressed by gzip, but got %q: %w",
			desc.Digest, desc.MediaType, compression, errUnsupportedLayerFormat)
	}

	ra, err := b.contentStore.ReaderAt(ctx, desc)
	if err != nil {
		return nil, nil, err
	}
	defer ra.Close()
	sr := io.NewSectionReader(ra, 0, desc.Size)

	tmpFile, err := os.CreateTemp("", "tmp.*")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmpFile.Name())
	n, err := io.Copy(tmpFile, sr)
	if err != nil {
		return nil, nil, err
	}
	if n != desc.Size {
		return nil, nil, errors.New("the size of the temp file doesn't match that of the layer")
	}

	ztoc, err := BuildZtoc(tmpFile.Name(), spanSize, b.buildToolIdentifier)
	if err != nil {
		return nil, nil, err
	}

	ztocReader, ztocDesc, err := NewZtocReader(ztoc)
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("layer %s -> ztoc %s\n", desc.Digest, ztocDesc.Digest)

	ztocDesc.MediaType = SociLayerMediaType
	ztocDesc.Annotations = map[string]string{
		IndexAnnotationImageLayerMediaType: ocispec.MediaTypeImageLayerGzip,
		IndexAnnotationImageLayerDigest:    desc.Digest.String(),
	}

	return ztocReader, &ztocDesc, err
}
