# Before Competition (0 hour)
* List of passwords for team to use throughout competition. Once created we can just refer to the passwords by their number in the list instead of saying them outloud for others to hear.
* Test file sharing
* Test session sharing
* Test chat (if needed)
* Create any scripts and make them available to bring into competition per rules

# First 5 minutes
* Start scans of targets and our own blue team. Fast all ports scan followed by more detailed service and script scans
* Create ssh keys to drop into authorized keys for any systems where we get control
* Begin DNS recon

# First 30 minutes
* Begin review of scans and look for quick wins of exposed ports and services
* Assist blue team in evaluating their external scan results

# Section here about what to do when...
* you get rce
* a foothold
* rdp/ssh access

# Other strategy topics
* hosting payloads
* downloading (or at least referencing  for in memory execution) and executing payloads and scripts

# Fun with Flags
<img src="https://user-images.githubusercontent.com/71292375/190544369-6cd1078b-a038-490d-8cc7-4813395123fe.png" alt="fun" width="325"/>

* overwrite flags with [scripts](https://github.com/acavedine/RT_Strategy/blob/main/RT.md#linux-file-write-script), [command hijacking](https://github.com/acavedine/RT_Strategy/blob/main/RT.md#malicious-binary-replacement), simple redirections using `echo flag_value > flag_file` 

