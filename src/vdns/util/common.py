import os
import pwd
import grp

def write_file(fn, contents, perms=None, owner=None, group=None):
    if perms:
        perms2=perms
    else:
        perms2=0o666

    fd=os.open(fn, os.O_CREAT | os.O_RDWR, perms2)

    # Bypass umask
    if perms:
        os.fchmod(fd, perms)

    if owner or group:
        if owner:
            pw=pwd.getpwnam(owner)
            uid=pw.pw_uid
        else:
            uid=-1

        if group:
            gr=grp.getgrnam(group)
            gid=gr.gr_gid
        else:
            gid=-1

        os.fchown(fd, uid, gid)

    f=os.fdopen(fd, 'w')
    f.write(contents)

    f.close()

if __name__=="__main__":
    write_file('/tmp/test1', 'teeeeeest')

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

