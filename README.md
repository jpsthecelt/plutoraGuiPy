This is an example of a Tkinter GUI-based on programmatically reading an existing record, 
displaing it, allowing update (through the GUI) and 'pushing' some JSON 
object into Plutora.  

Programmed in Python, and using requests, this takes commandline parameters of form 
    '-i', 'config_filename' - 'initial Config filename '
    '-p', 'post_target_values' - 'filename containing JSON object prototype'
    '-c', 'release_id' - 'release-id of release to copy'
    '-f', action='store' dest='field_names_file' - 'name of file containing field-names'
    "--gui", default=True - 'store_true'
    
The credentials from the credentials file are used to log into Plutora.

	1.20.17-jps

