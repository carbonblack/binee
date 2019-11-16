package util

import "gopkg.in/yaml.v2"
import "io/ioutil"

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
