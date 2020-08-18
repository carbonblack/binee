package windows

const (
	SELF_PROCESS_ID = 0xFFFFFFFF
	//Suffices
	PROCESS_ID_SUFFIX = "pid_"
	THREAD_ID_SUFFIX  = "tid_"
	WINDOW_ID         = "uuid_"
	FILEMAP_ID        = "uuid_"
	SECTIONMAP_ID     = "uuid_"

	//Objects
	PROCESS    = "process"
	THREAD     = "thread"
	WINDOW     = "window"
	FILEMAP    = "filemap"
	SECTIONMAP = "sectionmap"

	//Verbs
	TARGETS          = "targets"
	ALLOCATED_MEMORY = "allocatedMemory"
	WROTE_BYTES      = "wroteBytes"
	OWNS             = "owns"
	IS               = "is"
	HAS              = "has"
	CREATED          = "created"
	QUEUED           = "queued"
	LOCATES_WINDOW   = "locatesWindow"
	SEARCHES         = "searches"
	CREATED_FILEMAP  = "createFileMap"
	MAPPEDFILE       = "mappedFile"
	MAPPEDSECTION    = "mappedSection"
)
