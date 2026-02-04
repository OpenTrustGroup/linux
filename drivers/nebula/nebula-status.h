/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2021 GoldenRiver Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __LINUX_NEBULA_STATUS_H
#define __LINUX_NEBULA_STATUS_H

typedef enum nbl_status {
	kNblOk = 0,
	kNblErrGeneric = -1,
	kNblErrNotFound = -2,
	kNblErrNotReady = -3,
	kNblErrNoMsg = -4,
	kNblErrNoMemory = -5,
	kNblErrAlreadyStarted = -6,
	kNblErrNotValid = -7,
	kNblErrInvalidArgs = -8,
	kNblErrNotEnoughBuffer = -9,
	kNblErrNotSuspended = -10,
	kNblErrObjectDestroyed = -11,
	kNblErrNotBlocked = -12,
	kNblErrTimedOut = -13,
	kNblErrAlreadyExists = -14,
	kNblErrChannelClosed = -15,
	kNblErrOffline = -16,
	kNblErrNotAllowed = -17,
	kNblErrBadPath = -18,
	kNblErrAlreadyMounted = -19,
	kNblErrIo = -20,
	kNblErrNotDir = -21,
	kNblErrNotFile = -22,
	kNblErrRecurseTooDeep = -23,
	kNblErrNotSupported = -24,
	kNblErrTooBig = -25,
	kNblErrCancelled = -26,
	kNblErrNotImplemented = -27,
	kNblErrChecksumFail = -28,
	kNblErrCrcFail = -29,
	kNblErrCmdUnknown = -30,
	kNblErrBadState = -31,
	kNblErrBadLen = -32,
	kNblErrBusy = -33,
	kNblErrThreadDetached = -34,
	kNblErrI2cNack = -35,
	kNblErrAlreadyExpired = -36,
	kNblErrOutOfRange = -37,
	kNblErrNotConfigured = -38,
	kNblErrNotMounted = -39,
	kNblErrFault = -40,
	kNblErrNoResources = -41,
	kNblErrBadHandle = -42,
	kNblErrAccessDenied = -43,
	kNblErrPartialWrite = -44,
	kNblErrCreateHandle = -1001,
	kNblErrCreateChildHandle = -1002,
	kNblErrMmap = -1003,
	kNblErrOutOfMem = -1004,
	kNblErrConflictArgs = -1005,
	kNblErrTaRunFailed = -1006,
} nbl_status;

#endif /* __LINUX_NEBULA_STATUS_H */
