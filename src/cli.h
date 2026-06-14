/*
 * cli.h - local line-oriented control console (stdin).
 *
 * Not the MeshCore over-the-mesh admin protocol - this is a local operator
 * console for changing radio parameters (frequency!), dumping stats and
 * neighbours, and triggering adverts without a recompile or restart.
 */
#ifndef MC_CLI_H
#define MC_CLI_H

#include <stdbool.h>
#include "config.h"
#include "mesh.h"
#include "identity.h"

typedef struct {
    mc_config_t   *cfg;
    mc_mesh_t     *mesh;
    mc_identity_t *id;
    const char    *config_path;
    bool           radio_ready;  /* false during self-test / before radio init */
    bool          *running;      /* set to false on quit */
} cli_ctx_t;

void cli_banner(const cli_ctx_t *ctx);
void cli_handle_line(cli_ctx_t *ctx, const char *line);

#endif /* MC_CLI_H */
