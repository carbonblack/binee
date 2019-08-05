package core

type LogManager struct {
	iocs map[string][]string `json:"iocs"`
}

func NewLogManager() *LogManager {
	return &LogManager{make(map[string][]string)}
}

func (self *LogManager) AddIoc(key, value string) {
	if _, ok := self.iocs[key]; ok {
		self.iocs[key] = append(self.iocs[key], value)
	} else {
		self.iocs[key] = make([]string, 0, 10)
		self.iocs[key] = append(self.iocs[key], value)
	}
}
