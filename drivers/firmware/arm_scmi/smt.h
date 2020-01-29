/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Linaro Ltd.
 * Copyright (C) 2019 ARM Ltd.
 */
#ifndef ARM_SCMI_SMT_H
#define ARM_SCMI_SMT_H

#include "common.h"

struct scmi_shared_mem;

/* Wait SMT buffer is free and Write write SCMI message into */
void scmi_smt_tx_prepare(struct scmi_shared_mem __iomem *shmem,
			 struct scmi_xfer *xfer);

/* Read the msg_header from the SMT buffer */
__le32 scmi_smt_read_msg_header(struct scmi_shared_mem __iomem *shmem);

/* Copy response message from STM buffer to target location */
void scmi_smt_fetch_response(struct scmi_shared_mem __iomem *shmem,
			     struct scmi_xfer *xfer);

/* Return whether SMT buffer contains data from the SCMI server */
bool scmi_smt_poll_done(struct scmi_shared_mem __iomem *shmem,
			struct scmi_xfer *xfer);

#endif /* ARM_SCMI_SMT_H */
