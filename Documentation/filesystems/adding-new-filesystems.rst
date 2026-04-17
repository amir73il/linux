.. SPDX-License-Identifier: GPL-2.0

.. _adding_new_filesystems:

Adding New Filesystems
======================

This document describes what is involved in adding a new filesystem to the
Linux kernel, over and above the normal submission advice in
:ref:`Documentation/process/submitting-patches.rst <submittingpatches>` and
:ref:`Documentation/process/submit-checklist.rst <submitchecklist>`.

Every filesystem merged into the kernel becomes the collective responsibility
of the VFS maintainers and the wider filesystem development community.
Experience has shown that filesystems which become unmaintained impose a
significant and ongoing burden: they are hard or impossible to test, they
block infrastructure changes because someone must update or preserve old APIs
for code that nobody is actively looking after, and they accumulate unfixed
bugs.  The requirements and expectations described here are informed by this
experience and are intended to ensure that new filesystems enter the kernel
on a sustainable footing.


Do You Need a New In-Kernel Filesystem?
---------------------------------------

Before proposing a new in-kernel filesystem, consider whether one of the
alternatives might be more appropriate.

 - If an existing in-kernel filesystem covers the same use case, improving it
   is generally preferred over adding a new implementation.  The kernel
   community favors incremental improvement over parallel implementations.

 - If the filesystem serves a niche audience or has a small user base, a FUSE
   (Filesystem in Userspace) implementation may be a better fit.  FUSE
   filesystems avoid the long-term kernel maintenance commitment and can be
   developed and released on their own schedule.

 - If kernel-level performance, reliability, or integration is genuinely
   required, make the case explicitly.  Explain who the users are, what the
   use case is, and why a FUSE implementation would not be sufficient.


Technical Requirements
----------------------

New filesystems are expected to use current kernel interfaces and practices.
Submitting a filesystem built on outdated APIs creates an immediate
maintenance debt and is likely to face pushback during review.

Use modern VFS interfaces
  New filesystems should use iomap rather than buffer heads for block mapping
  and I/O, folios rather than raw page operations for page cache management,
  and the filesystem context API (``fs_context``) for the mount path.  See
  ``Documentation/filesystems/iomap/index.rst`` for iomap documentation and
  ``Documentation/filesystems/mount_api.rst`` for the mount API.

Avoid deprecated interfaces
  Do not use interfaces listed in
  :ref:`Documentation/process/deprecated.rst <deprecated>`.  If the
  filesystem depends on an interface that is being phased out, plan for
  conversion before submission.

Provide userspace utilities
  A ``mkfs`` tool is expected so that the filesystem can be created and used
  by testers and users.  A ``fsck`` tool is strongly recommended; while not
  strictly required for every filesystem type, the ability to verify
  consistency and repair corruption is an important part of a mature
  filesystem.

Be testable
  The filesystem must be testable in a meaningful way.  The
  `fstests <https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git>`_
  framework (also known as xfstests) is the standard testing infrastructure
  for Linux filesystems and its use is highly recommended.  At a minimum,
  there must be a credible and documented way to test the filesystem and
  detect regressions.  When submitting, include a summary of test results
  indicating which tests pass, fail, or are not applicable.

Provide documentation
  A documentation file under ``Documentation/filesystems/`` describing the
  filesystem, its on-disk format, mount options, and any notable design
  decisions is recommended.


Community and Maintainership Expectations
-----------------------------------------

Merging a filesystem is a long-term commitment.  The kernel community
needs confidence that the filesystem will be actively maintained after it
is merged.

Identified maintainer
  The submission must include a ``MAINTAINERS`` entry with at least one
  maintainer (``M:``), a mailing list (``L:``), and a git tree (``T:``).
  The maintainer is expected to be the primary point of contact for the
  filesystem going forward.

Demonstrated commitment
  A track record of maintaining kernel code -- for example, in other
  subsystems -- significantly strengthens the case for a new filesystem.
  Maintainers who are already known and trusted within the community face
  less friction during review.

Sustained backing
  Major filesystems in Linux have organizational or corporate support behind
  their development.  Filesystems that depend entirely on volunteer effort
  face higher scrutiny about their long-term viability.

Responsiveness
  The maintainer is expected to respond to bug reports, address review
  feedback, and adapt the filesystem to VFS infrastructure changes such as
  folio conversions, iomap migration, and mount API updates.  Unresponsive
  maintainership is one of the primary reasons filesystems end up on the
  path to deprecation.

User base
  Clearly describe who the users of this filesystem are and the scale of the
  user base.  Filesystems with a very small or unclear user base face a
  harder path to acceptance and a higher risk of future deprecation.

A practical way to demonstrate many of the qualities above is to maintain the
filesystem out-of-tree for a period before requesting a merge.  This shows
sustained commitment, builds a visible user base, and gives reviewers
confidence that the code and its maintainer will persist after merging.
That said, it is recognized that for some filesystems the user base grows
significantly only after upstreaming, so a compelling case for expected
adoption can substitute for a large existing user base.


Submission Process
------------------

Send patches to the linux-fsdevel mailing list
(``linux-fsdevel@vger.kernel.org``).  CC the relevant VFS maintainers as
listed in the ``MAINTAINERS`` file under ``FILESYSTEMS (VFS and infrastructure)``.

Expect thorough review.  Filesystem code interacts deeply with the VFS, memory
management, and block layers, so reviewers will examine the code carefully.
Address all review feedback and be prepared for multiple revision cycles.

It may be appropriate to mark the filesystem as experimental in its Kconfig
help text for the first few releases to set expectations while the code
stabilizes in-tree.


Ongoing Obligations
-------------------

Merging is not the finish line.  Maintaining a filesystem in the kernel is an
ongoing commitment.

 - Adapt to VFS infrastructure changes.  The VFS layer evolves continuously;
   maintainers are expected to keep up with conversions such as folio
   migration, iomap adoption, and mount API updates.

 - Maintain test coverage.  As test suites evolve, the filesystem's test
   results should be kept current.

 - Handle security issues promptly.  Filesystems parse complex on-disk
   structures from potentially untrusted media and must treat security
   reports with urgency.

 - Filesystems that become unmaintained -- where the maintainer stops
   responding, infrastructure changes go unadapted, and testing becomes
   impossible -- are candidates for deprecation and eventual removal from
   the kernel.
