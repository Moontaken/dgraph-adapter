export declare const User = "\n  fragment UserFragment on User {\n    email\n    id\n    image\n    name\n    emailVerified\n  }\n";
export declare const Account = "\n  fragment AccountFragment on Account {\n    id\n    type\n    provider\n    providerAccountId\n    expires_at\n    token_type\n    scope\n    access_token\n    refresh_token\n    id_token\n    session_state\n  }\n";
export declare const Session = "\n  fragment SessionFragment on Session {\n    expires\n    id\n    sessionToken\n  }\n";
export declare const VerificationToken = "\n  fragment VerificationTokenFragment on VerificationToken {\n    identifier\n    token\n    expires\n  }\n";
//# sourceMappingURL=fragments.d.ts.map