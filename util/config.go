package util

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type GenericConfig struct {
	Root string `yaml:"root"`
}

func ReadGenericConfig(config string) (conf GenericConfig, err error) {
	var buf []byte
	if buf, err = ioutil.ReadFile(config); err == nil {
		err = yaml.Unmarshal(buf, &conf)
	}
	return
}
