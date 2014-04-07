#!/usr/bin/env python 

import git

'''
The intent of this script is to sync two remotes, where one remote has local branches,
Not existant on the other branch. (Keep Alice on one side of the mirror!!!)

Prerequisite:  a clone of gitpython from 4/4/2014, or access to Eric Chazan's gitpython repo (equivalent)

This script could be broken up into a module with classes if it is intended to be used in other
contexts, but this isn't my use case (And Pydev catches more errors outside of a class)

BOOTSTRAPPING (instructions in Bash):

# generate sungardas repo (example as cloudstack):
git clone https://<user_name>@bitbucket.org/echaz/cloudstack-sungard.git -o sungardas

# add the upstream repo:
git remote add upstream https://github.com/apache/cloudstack.git

'''

try :
    # ASSUMPTIONS, we could use some kinda kwargs type dynamicism if we need it in the future to change these.
    head_reference = 'HEAD'
    sungard_remote_str = 'sungardas'
    upstream_remote_str = 'upstream'
    main_branch = 'master'
    email_user = 'eric.chazan@sungardas.com'
    
    # log to send
    log_lines = []
    
    
    # return the name of the branch, splitting off the origin location from the string.
    def branch_name(ref):
        try:
            return str(ref).split('/', 1)[1]
        # heads:
        except:
            return str(ref)
    
    # debugging options:
    if True:
        import os
        os.environ["GIT_PYTHON_TRACE"] = "True"
    
    # load the local copy of the repo:
    # TODO:  allow others to use this too, not just me on my mac (environmental variable?):
    repo = git.Repo("/users/eric.chazan/edisondev/src/cloudstack-sungard", odbt=git.GitCmdObjectDB)
    
    
    # verify all remotes exist, and are appropriate:
    for remote in repo.remotes:
        sungardas_repo = repo.remotes[sungard_remote_str]
        upstream_repo = repo.remotes[upstream_remote_str]
    
    # first fetch from the repos to capture all updates in the sources
    sungardas_repo.fetch()
    upstream_repo.fetch()
    
    branches_to_push = []
    
    # point the repo to the 'main branch'
    try:
        # decouple if already pointing to it:
        repo.head.reference = repo.head.reference.commit
        
        # delete the thing:
        repo.delete_head(main_branch, force = True)
    except:
        pass
        
    # point the repo to this main branch:
    repo.head.reference = repo.create_head(path = main_branch, commit = upstream_repo.refs[main_branch])
    
    # do we have to push this branch?:
    if sungardas_repo.refs[main_branch].commit != repo.refs[main_branch]:
        branches_to_push.append(repo.head.reference)
    
    # delete the other things in the local repo, to ensure proper branch cleanliness:
    [repo.delete_head(branch, force = True) for branch in repo.heads if str(branch) not in [main_branch, head_reference]]
    
    # Collect a list of all of the upstream branches:
    upstream_branches = [branch_name(branch) for branch in upstream_repo.refs]
    sungardas_branches = [branch_name(branch) for branch in  sungardas_repo.refs]
    
    # Sort the different types of branches using a little bit of set theory
    existing_branches = []
    new_branches = []
    
    # deleted + sungardas branches        
    other_branches = [branch for branch in sungardas_branches if branch not in upstream_branches]
    other_branches.remove(head_reference)
    
    # create the new branches into the sungardas mirror:
    for branch in upstream_branches:
         
        #create reference 
        ref = repo.create_head(path = branch, commit = upstream_repo.refs[branch_name(branch)])
            
    # force push all created references 
    results = sungardas_repo.push(all=True, force = True)

    # appends the results to the log:
    log_lines.append('push result:')
    num_up_to_date = 0
    for result in results:
        if result.summary.startswith('[up to date]'):
            num_up_to_date += 1
        else:
            log_lines.append(str(result.remote_ref) + ' ' + result.summary[:-1])
    results_as_strings = [str(result.remote_ref) + ' ' + result.summary[:-1] for result in results]

    log_lines.append('number of unpushed branches: ' + str(num_up_to_date))
    
        
    # Leave these alone.  All the alice branches are here.
    # TODO: Detect and destroy upstream branch deletions (if possible)
    for branch in other_branches:
        log_lines.append("If " + str(branch) + " is not a private repo branch, consider removing it.")
    
    log_lines.append('done.')
except:
    import traceback
    log_lines.append(traceback.format_exc())

# TODO: make this an email:
print '\n'.join(log_lines)