package runtime

import "github.com/xtls/xray-core/core"

func newInstance(cfg *core.Config) (closer, error) {
	return core.New(cfg)
}
