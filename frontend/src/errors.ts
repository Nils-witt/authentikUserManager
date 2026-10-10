/** Returns a displayable message for a thrown value. */
export const errorMessage = (err: unknown) => (err instanceof Error ? err.message : String(err))
