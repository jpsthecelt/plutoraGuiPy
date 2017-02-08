This is an example of a Tkinter GUI-based on programmatically reading an existing record, 
displaing it, allowing update (through the GUI) and 'pushing' that JSON 
object back into Plutora.  

Programmed in Python, and using the requests library, this utility takes commandline parameters of form 
    '-i', 'config_filename' - 'initial Config filename '
    '-p', 'post_target_values.XXX' - 'filename containing JSON object values to consume'
          (note that XXX may be one of .sys, .rls, .chg, or .env) -- program will update 
          the appropriate entity.
    '-c', 'guid' - 'id of release, environment, system, etc to copy' (all fields 
          following on the commandline will be ignored)
    '-x', 'guid' - 'id of entity to delete.  e.g., to delete a particular environment, 
          the command-line would be something like:
                python plutoraGuiPy -i <configfile> -x environments/c9977c38-01c1-4ed8-a8d0-8d89465582db 
          (all fields following this on the commandline will be ignored).
    "--gui", default=True - 'store_true' (once found, the initial values are displayed
          in a GUI, so the user can verify them before update.  Otherwise, the update
          will be done silently)
    
The credentials from the credentials-init-file are used to log into Plutora.

	2.7.17-jps
	(original version: 1.24.17-jps)

