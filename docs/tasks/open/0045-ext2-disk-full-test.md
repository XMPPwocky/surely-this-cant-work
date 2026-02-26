# 0045: Add ext2 disk-full error path test

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/ext2-server, user/ktest
**Source:** Arch review 7, backlog item 23

## Description

There is no test for what happens when an ext2 filesystem runs out of free
blocks or inodes. The error paths in ext2-server's write/create operations
may silently fail or return incorrect errors. Add a ktest that fills a small
ext2 image to capacity and verifies the write error is reported correctly.
