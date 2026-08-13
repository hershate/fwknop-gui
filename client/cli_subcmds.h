/**
 * \file client/cli_subcmds.h
 *
 * \brief Friendly subcommand dispatch: `fwknop setup|knock|lint`.
 */
#ifndef FKO_CLI_SUBCMDS_H
#define FKO_CLI_SUBCMDS_H 1

/* Return codes from cli_handle_subcommand(). */
enum {
    CLI_SUB_NONE  = 0,  /* argv[1] is not a known subcommand */
    CLI_SUB_KNOCK = 1   /* `knock`: argv rewritten, caller continues normally */
};

/*
 * Inspect argv[1] for a known friendly subcommand and handle it:
 *   setup -> run the interactive wizard (plan Sec.7.1), then exit()
 *   lint  -> validate fwknoprc (and optional --access-conf), then exit()
 *   knock -> rewrite argv into the normal send flow
 *            (`fwknop -n <profile> -R ...`) and return CLI_SUB_KNOCK so the
 *            caller falls through to the existing pipeline.
 *   other -> return CLI_SUB_NONE (normal fwknop behavior).
 *
 * \param argc, argv     Original main() arguments.
 * \param new_argc       Out: rewritten argc (only meaningful for KNOCK).
 * \param new_argv       Out: rewritten argv (heap-allocated; only for KNOCK).
 * \return CLI_SUB_NONE or CLI_SUB_KNOCK (setup/lint exit and do not return).
 */
int cli_handle_subcommand(int argc, char **argv, int *new_argc, char ***new_argv);

#endif /* FKO_CLI_SUBCMDS_H */

/***EOF***/
