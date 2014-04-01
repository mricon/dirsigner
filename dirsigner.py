#!/usr/bin/python -tt
# Copyright (C) 2014 by The Linux Foundation and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__ = 'Konstantin Ryabitsev'

import os
import sys
import gpgme
import hashlib
import fnmatch
import logging
import anyjson

from io import BytesIO

from fcntl import lockf, LOCK_EX, LOCK_UN, LOCK_NB


VERSION = '0.1'
CHUNK_SIZE = 8192
HASH_ALGORITHMS = ('md5', 'sha1', 'sha256', 'sha512')

logger = logging.getLogger('dirsigner')


def parse_args():
    from optparse import OptionParser

    usage = '''usage: %prog [options]
    Iterate recursively through a tree and create signed checksum files
    '''

    op = OptionParser(usage=usage, version=VERSION)
    op.add_option('-v', '--verbose', dest='verbose', action='store_true',
                  default=False,
                  help='Be verbose and tell us what you are doing')
    op.add_option('-t', '--tree', dest='tree',
                  help='The tree to recursively scan')
    op.add_option('-a', '--hash-algorithm', dest='hash_algorithm',
                  default='sha256',
                  help=('Hashing algorithm to use (sha256 default, '
                        'but can be %s)' % ', '.join(HASH_ALGORITHMS)))
    op.add_option('-g', '--gnupghome', dest='gnupghome',
                  default=None,
                  help='Set GNUPGHOME to this path (default: use ~/.gnupg)')
    op.add_option('-x', '--exclude', dest='excludes', action='append',
                  default=[],
                  help='Exclude files matching this glob (can be used multiple times)')
    op.add_option('-l', '--log-file', dest='logfile',
                  default=None,
                  help='Path to the log file (default: %default)')
    op.add_option('-k', '--lock-file', dest='lockfile',
                  default='.dirsigner.lock',
                  help='Path to the lockfile (default: %default)')

    opts, args = op.parse_args()

    if not opts.tree:
        op.error('You must provide the path to recursively sign')

    if opts.hash_algorithm not in HASH_ALGORITHMS:
        op.error('Unsupported algorithm: %s' % opts.hash_algorithm)

    return opts, args


def load_status(statusfile):
    if os.path.exists(statusfile):
        logger.debug('Reading status file from %s' % statusfile)
        fh = open(statusfile, 'r')
        contents = fh.read()
        fh.close()
        status = anyjson.deserialize(contents)
        logger.debug('Status file contains %d entries' % len(status.keys()))
    else:
        logger.debug('No status file found, assuming initial run')
        status = {}

    return status


def save_status(statusfile, status):
    if not len(status) and os.path.exists(statusfile):
        logger.debug('Removing obsolete %s' % statusfile)
        os.unlink(statusfile)
        return

    logger.debug('Saving status into %s' % statusfile)
    logger.debug('Status contains %d entries' % len(status.keys()))
    contents = anyjson.serialize(status)
    fh = open(statusfile, 'w')
    fh.write(contents)
    fh.close()


def get_file_hash(full_path, hash_algorithm):
    if hash_algorithm == 'md5':
        m = hashlib.md5()
    elif hash_algorithm == 'sha1':
        m = hashlib.sha1()
    elif hash_algorithm == 'sha512':
        m = hashlib.sha512()
    else:
        m = hashlib.sha256()

    logger.debug('Opening %s for reading using %d-byte chunks' % (full_path, CHUNK_SIZE))
    with open(full_path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b''):
            m.update(chunk)

    return m.hexdigest()


def write_sums_file(root, found_files, status, hash_algorithm):
    # Clean out any stale sums files
    for supported_algorithm in HASH_ALGORITHMS:
        sums_file = os.path.join(root, supported_algorithm + 'sums.asc')
        if os.path.exists(sums_file):
            os.unlink(sums_file)

    if not len(found_files):
        return

    tfh = BytesIO()
    for full_path in found_files:
        filename = os.path.basename(full_path)
        checksum = status[full_path]['hash']
        tfh.write(('%s  %s\n' % (checksum, filename)).encode('utf-8'))

    tfh.seek(0)

    sums_file = os.path.join(root, hash_algorithm + 'sums.asc')
    cfh = open(sums_file, 'wb')

    ctx = gpgme.Context()
    ctx.armor = True
    ctx.sign(tfh, cfh, gpgme.SIG_MODE_CLEAR)

    tfh.close()
    cfh.close()
    logger.info('Wrote %s' % sums_file)


def sign_tree(tree, excludes, hash_algorithm):
    logger.info('Recursively scanning %s' % tree)

    # Make sure '*sums.asc' and .dirsigner.* are always in excludes
    if '*sums.asc' not in excludes:
        excludes.append('*sums.asc')
    if '.dirsigner.*' not in excludes:
        excludes.append('.dirsigner.*')

    logger.debug('Exclude list: %s' % ' '.join(excludes))

    for root, dirs, files in os.walk(unicode(tree), topdown=True):
        logger.debug('Entered %s' % root)

        statusfile = os.path.join(root, '.dirsigner.status.js')
        status = load_status(statusfile)

        found_files = []
        dir_changed = False

        for name in files:
            full_path = os.path.join(root, name)
            if os.path.islink(full_path):
                logger.debug('Ignoring symlink %s' % name)
                continue

            # Does it match excludes?
            excluded = False
            for exclude in excludes:
                if fnmatch.fnmatch(name, exclude) or fnmatch.fnmatch(full_path, exclude):
                    logger.debug('Excluding %s because it matches %s' % (full_path, exclude))
                    excluded = True
                    break
            if excluded:
                continue

            # Get stats on the file and compare to what we have in the status
            try:
                fstat = os.lstat(full_path)
            except OSError:
                logger.debug('Was not able to stat %s, ignoring' % full_path)
                continue

            found_files.append(name)
            (ctime, mtime, size, inode) = (fstat[9], fstat[8], fstat[6], fstat[1])

            # Is this path in status?
            changed = False
            if name in status.keys():
                # Do ctime, mtime and size match?
                # A bit verbose, but lets us log the exact reason
                if status[name]['ctime'] != ctime:
                    logger.info('File %s changed ctime' % name)
                    changed = True
                elif status[name]['mtime'] != mtime:
                    logger.info('File %s changed mtime' % name)
                    changed = True
                elif status[name]['size'] != size:
                    logger.info('File %s changed size' % name)
                    changed = True
                elif status[name]['inode'] != inode:
                    logger.info('File %s changed inode' % name)
                    changed = True
            else:
                logger.debug('No previous record of %s' % name)
                changed = True

            if changed:
                file_hash = get_file_hash(full_path, hash_algorithm)

                if name in status.keys():
                    if status[name]['hash'] != file_hash:
                        logger.info('%s hash of %s is: %s' % (hash_algorithm, full_path, file_hash))
                        dir_changed = True
                else:
                    logger.info('%s hash of %s is: %s' % (hash_algorithm, full_path, file_hash))
                    dir_changed = True

                status[name] = {
                    'ctime': ctime,
                    'mtime': mtime,
                    'size': size,
                    'inode': inode,
                    'hash': file_hash,
                    }

        # Weed out our existing status entries
        for entry in status.keys():
            if entry not in found_files:
                logger.info('File %s from status is no longer there' % entry)
                del(status[entry])
                dir_changed = True

        sums_file = os.path.join(root, hash_algorithm + 'sums.asc')
        if len(found_files) and not os.path.exists(sums_file):
            # Always generate one if we don't have it
            dir_changed = True

        if dir_changed:
            write_sums_file(root, found_files, status, hash_algorithm)
            # Save status after each changed dir
            save_status(statusfile, status)

        # Look at dirs and see if we need to exclude any of them
        to_rm = []
        for name in dirs:
            full_path = os.path.join(root, name)

            if os.path.islink(full_path):
                logger.debug('Ignoring symlink %s' % name)
                continue

            excluded = False
            for exclude in excludes:
                if fnmatch.fnmatch(name, exclude) or fnmatch.fnmatch(full_path, exclude):
                    logger.debug('Excluding %s because it matches %s' % (full_path, exclude))
                    excluded = True
                    break
            if excluded:
                to_rm.append(name)
                continue

        for name in to_rm:
            dirs.remove(name)


def main():
    opts, args = parse_args()

    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)

    if opts.verbose:
        ch.setLevel(logging.INFO)
    else:
        ch.setLevel(logging.CRITICAL)

    logger.addHandler(ch)

    if opts.logfile is not None:
        ch = logging.FileHandler(opts.logfile)
        formatter = logging.Formatter("[%(process)d] %(asctime)s - %(levelname)s - %(message)s")
        ch.setFormatter(formatter)

        ch.setLevel(logging.DEBUG)
        logger.addHandler(ch)

    if opts.gnupghome is not None:
        logger.info('Setting GNUPGHOME to %s' % opts.gnupghome)
        os.environ['GNUPGHOME'] = opts.gnupghome

    lock_fh = open(opts.lockfile, 'w')
    logger.debug('Obtaining exclusive lock for %s' % opts.lockfile)

    try:
        lockf(lock_fh, LOCK_EX|LOCK_NB)
    except IOError, ex:
        logger.info('Could not obtain exclusive lock, assuming another process is running.')
        sys.exit(0)

    logger.debug('Lock obtained')

    sign_tree(opts.tree, opts.excludes, opts.hash_algorithm)
    lockf(lock_fh, LOCK_UN)
    logger.debug('Lock released')


if __name__ == '__main__':
    main()