Config reloads no longer hang forever when a changed sink stops polling its input. Vector now waits up to the graceful shutdown limit (`--graceful-shutdown-limit-secs`, 60 seconds by default) for the old sink to finish, then drops it, along with any events it had already taken from its buffer, and starts the new sink on the same buffer. Previously the reload waited forever and the process stopped applying config changes. Ported from upstream vectordotdev/vector#26688.

authors: JuanMantica45
