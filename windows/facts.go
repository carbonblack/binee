package windows

const (
	FCT_SELF_PROCESS_ID  = 0xFFFFFFFF
	FCT_PROCESS_NOTFOUND = 0xFFFFFFFE
	//Suffices
	FCT_PROCESS_ID_SUFFIX = "pid_0x%x"
	FCT_THREAD_ID_SUFFIX  = "tid_0x%x"
	FCT_UUID_ID_SUFFIX    = "uuid_0x%x"
	FCT_UUID_NAME_SUFFIX  = "uuid_%s"

	//Objects
	FCT_PROCESS    = "process(" + FCT_PROCESS_ID_SUFFIX + ")."
	FCT_THREAD     = "thread(" + FCT_THREAD_ID_SUFFIX + ")."
	FCT_WINDOW     = "window(%s)."
	FCT_FILEMAP    = "filemap(%s)."
	FCT_SECTIONMAP = "sectionmap(%s)."

	//Verbs
	FCT_TARGETS          = "targets(" + FCT_PROCESS_ID_SUFFIX + "," + FCT_PROCESS_ID_SUFFIX + ")."
	FCT_ALLOCATED_MEMORY = "allocatedMemory(" + FCT_PROCESS_ID_SUFFIX + "," + FCT_PROCESS_ID_SUFFIX + ")."
	FCT_WROTE_BYTES_1    = "wroteBytes(" + FCT_PROCESS_ID_SUFFIX + ",0x%x,0x%x)."
	FCT_WROTE_BYTES_2    = "wroteBytes(%s,%s)."

	FCT_OWNS       = "owns(" + FCT_PROCESS_ID_SUFFIX + "," + FCT_THREAD_ID_SUFFIX + ")."
	FCT_THREAD_IS  = "is(" + FCT_THREAD_ID_SUFFIX + ",%s)."
	FCT_PROCESS_IS = "is(" + FCT_PROCESS_ID_SUFFIX + ",%s)."
	FCT_UUID_IS    = "is(" + FCT_UUID_NAME_SUFFIX + ",%s)."

	FCT_HAS       = "has(" + FCT_THREAD_ID_SUFFIX + ",0x%x)."
	FCT_HAS_QUEUE = "has(" + FCT_THREAD_ID_SUFFIX + ",queue_apc)."
	FCT_CREATED   = "created(" + FCT_PROCESS_ID_SUFFIX + "," + FCT_THREAD_ID_SUFFIX + ")."
	FCT_QUEUED    = "queued(" + FCT_PROCESS_ID_SUFFIX + "," + FCT_THREAD_ID_SUFFIX + ")."
	FCT_SEARCHES  = "searches(" + FCT_PROCESS_ID_SUFFIX + "," + FCT_UUID_NAME_SUFFIX + "," + FCT_PROCESS_ID_SUFFIX + ")."

	LOCATES_WINDOW      = "locatesWindow"
	FCT_CREATED_FILEMAP = "createdFileMap(%s,%s)."
	FCT_MAPPEDFILE      = "mappedFile(%s,%s,%s)."
	FCT_MAPPEDSECTION   = "mappedSection(%s,%s,%s)."
)
