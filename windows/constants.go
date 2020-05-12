package windows

const (
	GENERIC_ALL      = 0x10000000
	GENERIC_EXECUTE  = 0x20000000
	GENERIC_WRITE    = 0x40000000
	GENERIC_READ     = 0x80000000
	CREATE_NEW       = 0x1
	CREATE_ALWAYS    = 0x2
	CREATE_SUSPENDED = 0x4
	//
	ERROR_SUCCESS        = 0x0
	ERROR_FILE_NOT_FOUND = 0x2
	ERROR_INVALID_HANDLE = 0x6
	ERROR_MORE_DATA      = 0xea
	ERROR_NO_MORE_ITEMS  = 0x103
	//
	REG_NONE      = 0x0
	REG_SZ        = 0x1
	REG_EXPAND_SZ = 0x2
	REG_BINARY    = 0x3
	REG_DWORD     = 0x4
	REG_LINK      = 0x6
	REG_MULTI_SZ  = 0x7
	REG_QWORD     = 0xb
	//
	STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
	//
	STATUS_SUCCESS   = 0x0
	STATUS_WAIT_0    = 0x0
	STATUS_WAIT_1    = 0x1
	STATUS_WAIT_2    = 0x2
	STATUS_WAIT_3    = 0x3
	STATUS_WAIT_63   = 0x3f
	STATUS_ABANDONED = 0x80

	//
	WAIT_OBJECT_0    = 0x00000000
	WAIT_ABANDONED_0 = 0x00000080
	WAIT_TIMEOUT     = 0x00000102
	WAIT_FAILED      = 0xFFFFFFFF
)

var EN_LOCALE = map[int]string{
	//https://docs.microsoft.com/en-us/windows/desktop/Intl/code-page-identifiers
	//https://github.com/wine-mirror/wine/blob/master/include/winnls.h
	//http://www.borgendale.com/locale/en_US.htm
	0x1004: "utf-8",
	0x1005: "\x00",
	0x1009: "1",
	0x14:   "$",
	0x19:   "2",
	0x1b:   "0",
	0x1c:   "0",
	0x1d:   "/",
	0x1e:   ":",
	0x1f:   "%m/%d/%y",
	0x20:   "%B %d, %Y",
	0x23:   "0",
	0x25:   "0",
	0x28:   "am",
	0x29:   "pm",
	0x2a:   "Monday",
	0x2b:   "Tuesday",
	0x2c:   "Wednesday",
	0x2d:   "Thursday",
	0x2e:   "Friday",
	0x2f:   "Saturday",
	0x30:   "Sunday",
	0x31:   "Mon",
	0x32:   "Tue",
	0x33:   "Wed",
	0x34:   "Thu",
	0x35:   "Fri",
	0x36:   "Sat",
	0x37:   "Sun",
	0x38:   "January",
	0x39:   "February",
	0x3a:   "March",
	0x3b:   "April",
	0x3c:   "May",
	0x3d:   "June",
	0x3e:   "July",
	0x3f:   "August",
	0x40:   "September",
	0x41:   "October",
	0x42:   "November",
	0x43:   "December",
	0x44:   "Jan",
	0x45:   "Feb",
	0x46:   "Mar",
	0x47:   "Apr",
	0x48:   "May",
	0x49:   "Jun",
	0x4a:   "Jul",
	0x4b:   "Aug",
	0x4c:   "Sep",
	0x4d:   "Oct",
	0x4e:   "Nov",
	0x4f:   "Dec",
	0xc:    "'",
	0xe:    ".",
	0xf:    ",",
}

func GetLocale(id int) map[int]string {
	if id == 0x409 {
		return EN_LOCALE
	}
	//...
	return EN_LOCALE
}
