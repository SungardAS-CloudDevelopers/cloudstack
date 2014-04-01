from git import Repo, GitCmdObjectDB

'''
The intent of this script is to sync two remotes, where one remote has local branches,
Not existant on the other branch

This script could be broken up into a module with classes if it is intended to be used in other
contexts, but this isn't my use case (And Pydev catches more errors outside of a class)

BOOTSTRAPPING (instructions in Bash):

# generate sungardas repo (example as cloudstack):
git clone https://<user_name>@bitbucket.org/echaz/cloudstack-sungard.git -o sungardas

# add the upstream repo:
git remote add upstream https://github.com/apache/cloudstack.git

# do one fetch (i don't know why)
git fetch -v upstream

'''

# return the name of the branch, splitting off the origin location from the string.
def branch_name(ref):
    return str(ref).split('/', 1)[1]

# determines if the commit was pushed by a SungardAS member or other.  This is dark magic.
# failures will terminate process
class IdentifyCommitter(object):
    def __init__(self):
        # list of users verified as having committed to the private repo.
        self.identified_users = []

    def IdentifyBitBucketCommitter(self,sha):
        # TODO later: 
        raise NotImplementedError("OH NOES!")
    
    def IdentifyGitHubCommitter(self,sha):
        # TODO if necessary.  command line arg?
        raise NotImplementedError("OH NOES!")
    
    def IdentifyCommitter(self,sha):
        return self.IdentifyBitBucketCommitter(sha)


# debugging options:
if True:
    import os
    os.environ["GIT_PYTHON_TRACE"] = "True"

# load the local copy of the repo:
# TODO:  allow others to use this too, not just me on my mac:
head_reference = 'HEAD'
repo = Repo("/users/eric.chazan/edisondev/src/cloudstack-sungard", odbt=GitCmdObjectDB)

# TODO: Bootstrap a repo if it doesn't already exist
# TODO: Destroy and recheck repo to make sure this code is properly functional
# TODO: Detect and destroy upstream branch deletions


# verify all remotes exist, and are appropriate:
for remote in repo.remotes:
    if str(remote) == 'sungardas':
        sungardas_repo = remote
    elif str(remote) == 'upstream':
        upstream_repo = remote

if sungardas_repo is None:
    raise Exception('Sungardas Repo not found!  Terminating')
if upstream_repo is None:
    raise Exception ("Upstream Repo not found!  Terminating")

# first fetch from the repos to capture all updates in the sources
sungardas_repo.fetch()
upstream_repo.fetch()

# Collect a list of all of the upstream branches:
upstream_branches = [branch_name(branch) for branch in upstream_repo.refs]
sungardas_branches = [branch_name(branch) for branch in  sungardas_repo.refs]

# Sort the different types of branches using a little bit of set theory
existing_branches = []
new_branches = []

for branch in upstream_branches:
    if branch in sungardas_branches:
        existing_branches.append(branch)
    else:
        new_branches.append(branch)
 
# deleted + sungardas branches        
other_branches = [branch for branch in sungardas_branches if branch not in upstream_branches]
if head_reference in other_branches:
    other_branches.remove(head_reference)

'''
for new_branch in new_branches:
    print 'this is teh new branch ' + str(new_branch)
for existing_branch in existing_branches:
    print 'this is teh existing branch ' + str(existing_branch)
for other_branch in other_branches:
    print 'this is teh other branch ' + str(other_branch)
'''

# create the new branches into the sungardas mirror:
for branch in new_branches:
    # TODO:
    pass
for branch in existing_branches:
    # TODO: 
    pass
for branch in other_branches:
    # TODO:
    pass
    
    
    
