// CDMI over MCP: prompts.
//
// A prompt of the Model Context Protocol is a named, user-initiated template
// that expands into messages telling a model how to carry out a whole job with
// the tools. It is "user-controlled, meaning [prompts] are exposed from servers
// to clients with the intention of the user being able to explicitly select
// them for use"; a client typically offers them as slash commands.
//
// The CDMI over MCP subclause standardized the five tools and left prompts out,
// so what is here is an extension of this server's and not a requirement of the
// document — offered as a proposal for a future revision of the subclause
// (cvwm R2).
//
// Each prompt wraps a job whose *rules* a bare tool call cannot enforce. They
// are not conveniences: every one of them encodes a discipline that produced a
// real defect in this project or that the document states as a requirement a
// client must meet in a particular order. The owner bug — an access control
// entry appended rather than the list replaced, and the principal
// realm-qualified — is the reason grant_access exists; the export ordering is
// the reason publish_container_http exists; the capability check before a move
// is the reason move_object exists, and is the subclause's own worked example
// of a condition.
//
// One rule this binding follows for tools is deliberately not followed here.
// The tool list is "the list of [the tools table] for every CDMI client of every
// CDMI server", published whether or not each operation is implemented;
// capabilities publish only what is implemented. Prompts sit with capabilities:
// the prompts capability is advertised only because the responder is here, so a
// client's prompts/list is never answered with a method error after the
// capability said it would work.

/** An argument of a prompt, as prompts/list reports it. */
interface PromptArgument {
  name: string;
  description: string;
  required: boolean;
}

/**
 * A prompt: what a client lists, and how it expands.
 *
 * "reads" names the objects whose current state is handed to the model with the
 * instructions, as the embedded resource blocks of prompts/get. A prompt that
 * edits a structured field is given that field's current value rather than being
 * left to guess it — which is the whole of the owner bug: an access control list
 * was replaced because the party writing it did not have the one it was
 * replacing.
 */
export interface Prompt {
  name: string;
  title: string;
  description: string;
  arguments: PromptArgument[];
  /** The one-line account of this expansion, which the result reports. */
  summary: (a: Record<string, string>) => string;
  /** The instructions, as the text of the first message. */
  text: (a: Record<string, string>) => string;
  /** The addresses whose current state is embedded, resolved against the base. */
  reads?: (a: Record<string, string>) => string[];
}

const uriArgument: PromptArgument = {
  name: "uri",
  description: 'The namespace path of the object, as "/reports/q3.txt".',
  required: true,
};

const principalArgument: PromptArgument = {
  name: "principal",
  description: 'The principal, realm-qualified, as "bob@SNIA.LOCAL". A bare name is not a ' +
    "principal any domain resolves.",
  required: true,
};

export const PROMPTS: Prompt[] = [
  {
    name: "grant_access",
    title: "Grant a principal access",
    description: "Add an ALLOW entry to an object's cdmi_acl for a principal, preserving the " +
      "entries already there.",
    arguments: [
      uriArgument,
      principalArgument,
      {
        name: "access",
        description: 'What to grant: "read", "write" or "full".',
        required: true,
      },
    ],
    summary: (a) => `Grant ${a.principal} ${a.access} access to ${a.uri}`,
    reads: (a) => [`${a.uri}?metadata=cdmi_acl`],
    text: (a) =>
      `Grant the principal ${a.principal} ${a.access} access to the object at ${a.uri}.\n\n` +
      "The object's current cdmi_acl is given below. Work from it, and observe the following, " +
      "each of which has been got wrong here before:\n\n" +
      "1. APPEND an entry. Do not replace the list. An update whose body carries a cdmi_acl " +
      "replaces the whole list, so the body you send must contain every entry that is there " +
      "now plus the new one.\n" +
      "2. Keep the order. An access control list is evaluated in order and a DENY entry " +
      "earlier in the list defeats an ALLOW later in it, so a new ALLOW goes after the " +
      "existing DENY entries and before nothing that was there.\n" +
      "3. Keep the OWNER@ entry first, and do not modify it. An object whose owner has lost " +
      "its own entry cannot have the list repaired by its owner.\n" +
      "4. The identifier is realm-qualified. A bare name is not a principal any domain " +
      "resolves, and an entry naming one grants nothing and reports no error.\n" +
      '5. For a container object, "read" access means the LIST_CONTAINER permission and not ' +
      "READ_OBJECT alone: a principal granted READ_OBJECT on a container cannot list its " +
      "children. Set both where the caller means to allow browsing.\n\n" +
      "Send the change as a single cdmi_update whose mode is replace-fields and whose uri " +
      "selects metadata=cdmi_acl, so that nothing outside the access control list is touched. " +
      "Then read the field back and show the caller the list as it now stands.",
  },
  {
    name: "revoke_access",
    title: "Revoke a principal's access",
    description: "Remove a principal's entries from an object's cdmi_acl, leaving every other " +
      "entry as it was.",
    arguments: [uriArgument, principalArgument],
    summary: (a) => `Revoke ${a.principal}'s access to ${a.uri}`,
    reads: (a) => [`${a.uri}?metadata=cdmi_acl`],
    text: (a) =>
      `Remove the access control entries naming ${a.principal} from the object at ${a.uri}.\n\n` +
      "The object's current cdmi_acl is given below. Observe the following:\n\n" +
      "1. Remove ONLY the entries whose identifier is that principal. Every other entry stays, " +
      "in the order it is in.\n" +
      "2. Do not remove the OWNER@ entry, and do not remove an entry naming a group merely " +
      "because the principal is a member of it: revoking a group's access revokes it for " +
      "every member.\n" +
      "3. Adding a DENY entry is not the same as removing an ALLOW. A DENY for that principal " +
      "refuses it whatever a later ALLOW says, including an ALLOW that names a group the " +
      "caller may later rely on. If the caller wants the principal refused rather than merely " +
      "not granted, say so and ask which is meant.\n" +
      "4. Where the principal has no entry, change nothing and say so. Do not send an update " +
      "that rewrites the list to the same value.\n\n" +
      "Send the change as a single cdmi_update whose mode is replace-fields and whose uri " +
      "selects metadata=cdmi_acl.",
  },
  {
    name: "publish_container_http",
    title: "Publish a container over HTTP",
    description: "Place an HTTP export on a container object so that its objects are served " +
      "at a URI path.",
    arguments: [
      { ...uriArgument, description: 'The namespace path of the container object, as "/public/".' },
      {
        name: "path",
        description: 'The URI path to serve it beneath, beginning and ending with a solidus, ' +
          'as "/files/".',
        required: true,
      },
      {
        name: "anonymous_read",
        description: 'Whether a request presenting no credentials is read as ANONYMOUS@: ' +
          '"true" or "false".',
        required: false,
      },
    ],
    summary: (a) => `Publish ${a.uri} over HTTP at ${a.path}`,
    reads: (a) => [`${a.uri}?exports`, "/cdmi_capabilities/container/"],
    text: (a) =>
      `Place an HTTP export on the container object at ${a.uri}, serving it beneath the URI ` +
      `path ${a.path}.\n\n` +
      "The container's current exports field and the container capabilities are given below. " +
      "Observe the following:\n\n" +
      "1. Set the export list BEFORE the container is filled, where the container is new. An " +
      "export placed on a container that already holds objects publishes all of them at once, " +
      "and the caller may not have inspected what is in there.\n" +
      "2. The exports field is a list and an update replaces it. Carry over every entry that " +
      "is there now.\n" +
      "3. An export grants nothing. Neither anonymous_read nor auth_method grants access: " +
      "ANONYMOUS@ obtains only what the access control lists grant it. If the caller wants the " +
      "objects readable, the cdmi_acl of the container must grant that principal " +
      "LIST_CONTAINER on the container, and READ_OBJECT on the objects beneath it — " +
      "LIST_CONTAINER alone does not permit reading a child's value, and READ_OBJECT alone " +
      "does not permit listing. Use the grant_access prompt for that, and do it as a separate, " +
      "stated step so the caller sees that access is being granted.\n" +
      "4. read_only defaults to true, which serves GET, HEAD and OPTIONS alone. Setting it " +
      "false requires the cdmi_export_http_write capability, and publishes a writable " +
      "surface — say so before doing it.\n" +
      "5. Within one origin, a path may not equal, prefix, or be prefixed by the path of " +
      "another export. Check the entries already in the list against the path asked for, and " +
      "report the conflict rather than sending an update that will be refused.\n" +
      '6. Listing an "http" origin with an auth_method other than "anonymous" transmits ' +
      "credentials without confidentiality. Say so if that is what is being asked for.\n\n" +
      "Confirm from the capabilities that the export type and any optional field you intend " +
      "to set are supported, then send one cdmi_update whose mode is replace-fields and whose " +
      "uri selects exports.",
  },
  {
    name: "provision_home",
    title: "Provision a principal's home container",
    description: "Make a container object owned by a principal and closed to everyone else.",
    arguments: [principalArgument, {
      name: "under",
      description: 'The container object to make it in, as "/home/". The principal\'s name ' +
        "is the child name.",
      required: false,
    }],
    summary: (a) => `Provision a home container for ${a.principal}`,
    text: (a) =>
      `Make a home container object for ${a.principal}${a.under ? ` under ${a.under}` : ""}.\n\n` +
      "Observe the following, in this order:\n\n" +
      "1. Create the container object first, with cdmi_create and a representation of " +
      "cdmi-container, and give it onlyIfAbsent so that an existing home is not replaced. A " +
      "create without onlyIfAbsent replaces an object that is there.\n" +
      "2. Set cdmi_owner to the principal, realm-qualified.\n" +
      "3. Then set the cdmi_acl: one entry granting OWNER@ what the owner needs, and nothing " +
      "granting EVERYONE@. Do NOT rely on the container inheriting a closed list from its " +
      "parent — read the parent's cdmi_acl and see what it actually grants before you assume " +
      "the new container is closed.\n" +
      "4. Read the container back and show the caller its cdmi_owner and cdmi_acl, so that a " +
      "home that is open to everyone is visible now rather than later.\n\n" +
      "Do not put a value in the container and do not create anything beneath it.",
  },
  {
    name: "place_under_dac",
    title: "Place an object under delegated access control",
    description: "Set an object's delegated access control provider, which moves the " +
      "authorization decision to that provider.",
    arguments: [uriArgument, {
      name: "provider_uri",
      description: "The absolute URI of the delegated access control provider.",
      required: true,
    }],
    summary: (a) => `Place ${a.uri} under the delegated access control of ${a.provider_uri}`,
    reads: (a) => [`${a.uri}?metadata`],
    text: (a) =>
      `Place the object at ${a.uri} under the delegated access control provider at ` +
      `${a.provider_uri}.\n\n` +
      "This moves the authorization decision for the object away from its access control list " +
      "to that provider. Tell the caller that before you do it.\n\n" +
      "Observe the following:\n\n" +
      "1. Set cdmi_dac_uri and cdmi_dac_certificate TOGETHER, in one update. An object with " +
      "the URI and no certificate names a provider whose responses cannot be verified, and " +
      "the server will not use it — so the object is left neither under its access control " +
      "list nor under the provider.\n" +
      "2. The certificate is the provider's, and is the one that signs the provider's " +
      "decisions. Do not invent it, and do not copy one from another object without being " +
      "told the two objects share a provider.\n" +
      "3. Confirm the cdmi_dac capability is present before sending the update.\n" +
      "4. After the update, read the object's metadata back and confirm both items are there.\n\n" +
      "The object's current metadata is given below.",
  },
  {
    name: "audit_domain",
    title: "Audit a domain",
    description: "Read a domain object and summarise who it holds and what they are granted.",
    arguments: [{
      name: "domain",
      description: 'The namespace path of the domain object, as "/cdmi_domains/sales/".',
      required: true,
    }],
    summary: (a) => `Audit the domain ${a.domain}`,
    reads: (a) => [`${a.domain}?metadata`, `${a.domain}?children`],
    text: (a) =>
      `Summarise the domain object at ${a.domain} for the caller.\n\n` +
      "Report, from the state given below and from any further read you need:\n\n" +
      "1. The principals the domain holds, from cdmi_domain_userinfo, and what each is " +
      "granted.\n" +
      "2. The access control list of the domain object itself, and who may change the domain.\n" +
      "3. Whether the domain delegates its authorization, from cdmi_dac_uri — a domain under " +
      "delegated access control is not audited by reading its access control lists alone, and " +
      "say so rather than reporting a picture that is not the operative one.\n" +
      "4. Any child domain, since a summary of a domain that omits the domains beneath it " +
      "understates what it governs.\n\n" +
      "This is a read-only job. Do not change anything, and do not offer to.",
  },
  {
    name: "move_object",
    title: "Move an object",
    description: "Move an object to another name, or achieve the same result where the server " +
      "does not implement a move.",
    arguments: [uriArgument, {
      name: "destination",
      description: 'The namespace path to move it to, as "/archive/q3.txt".',
      required: true,
    }],
    summary: (a) => `Move ${a.uri} to ${a.destination}`,
    reads: () => ["/cdmi_capabilities/container/"],
    text: (a) =>
      `Move the object at ${a.uri} to ${a.destination}.\n\n` +
      "Do this in the following order, which matters:\n\n" +
      "1. Read the capabilities of the destination's parent container and check for " +
      "cdmi_move_dataobject (or cdmi_move_container, for a container object). The " +
      "capabilities are given below where the destination is beneath the same container.\n" +
      "2. Where the capability is present, perform the move and stop.\n" +
      "3. Where it is ABSENT, do not simply report failure, and do not silently do something " +
      "else. Tell the caller that copying the object and deleting the original achieves a " +
      "similar result but that THE OBJECT ID IS NOT PRESERVED — anything holding a reference " +
      "to the object by its ID, or an object ID URI, will no longer reach it. Ask whether to " +
      "proceed on that basis.\n" +
      "4. Where the caller agrees, copy first and verify the copy — read it back and compare " +
      "its cdmi_size and cdmi_hash with the original's — and delete the original only after " +
      "that. A delete before a verified copy loses the object.\n\n" +
      "Do not overwrite an object at the destination. Create with onlyIfAbsent, and report a " +
      "collision rather than resolving it.",
  },
  {
    name: "drain_queue",
    title: "Read and remove values from a queue",
    description: "Take values off a queue object without losing any and without removing more " +
      "than were read.",
    arguments: [
      { ...uriArgument, description: 'The namespace path of the queue object, as "/jobs/in".' },
      {
        name: "count",
        description: "How many values to take. Where absent, take what one read returns.",
        required: false,
      },
    ],
    summary: (a) => `Take ${a.count ?? "the available"} values off the queue ${a.uri}`,
    text: (a) =>
      `Take values off the queue object at ${a.uri}` +
      `${a.count ? `, ${a.count} of them` : ""}.\n\n` +
      "Reading a queue does not remove what was read, and removing is a separate operation. " +
      "The order is not negotiable:\n\n" +
      "1. READ the values first, with cdmi_read, and note the valuerange the result reports. " +
      "The server applies its own bound to how many a read returns, so you may get fewer than " +
      "you asked for — the valuerange says what you actually have.\n" +
      "2. Only once the values are in hand, delete THE SAME RANGE, by supplying that range in " +
      "the uri of a cdmi_delete.\n" +
      "3. Do NOT delete by a count. A delete by count removes that many FURTHER values each " +
      "time it is called, so a delete by count after a read removes values that were never " +
      "read, and repeating it removes more. This is why the delete tool is annotated as not " +
      "idempotent.\n" +
      "4. Never delete before reading, and never delete a range wider than the one the read " +
      "reported. A value removed from a queue is gone.\n\n" +
      "Report to the caller the values taken and the range removed, so the two can be seen to " +
      "match.",
  },
  {
    name: "diagnose_refusal",
    title: "Diagnose a refusal",
    description: "Find out which of the three things refused an operation: the access token's " +
      "scope, the object's access control list, or an absent capability.",
    arguments: [
      uriArgument,
      {
        name: "operation",
        description: 'What was attempted, as "read", "update", "delete" or the name of a tool.',
        required: true,
      },
    ],
    summary: (a) => `Diagnose why ${a.operation} on ${a.uri} was refused`,
    reads: (a) => [`${a.uri}?metadata=cdmi_acl&metadata=cdmi_owner`, "/cdmi_capabilities/"],
    text: (a) =>
      `Work out why ${a.operation} on ${a.uri} was refused, and tell the caller which of ` +
      "three distinct things refused it. They are not interchangeable and the fix for each is " +
      "different:\n\n" +
      "1. THE SCOPE of the access token. A token lacking the scope an operation needs is " +
      "refused whatever the access control lists grant, and the condition names the scope " +
      "required. The fix is a new token, not a change to the object.\n" +
      "2. THE ACCESS CONTROL LIST of the object, evaluated for the principal the token " +
      "resolved to. Check the order of the entries: a DENY earlier in the list defeats an " +
      "ALLOW later in it, and an entry naming a bare rather than a realm-qualified principal " +
      "grants nothing. Check that the principal is the one you think it is.\n" +
      "3. AN ABSENT CAPABILITY. The operation is not implemented for that object, and the " +
      "condition names the capability in its cdmi_capability member and the capability object " +
      "to read in cdmi_capability_uri. No change to any access control list will help.\n\n" +
      "A fourth possibility: the object was not found because the principal is not permitted " +
      "to know it exists. A not-found condition where the caller believes the object is there " +
      "is a permission result, not evidence the object is absent.\n\n" +
      "The object's access control list and owner, and the capabilities, are given below. " +
      "Read the problem details document from the refusal if the caller has it: its type " +
      "member names the condition, and its extension members name the field, argument, or " +
      "capability at fault. Say which of the three it was, quote what you based that on, and " +
      "propose the one change that addresses it. Do not change anything.",
  },
  {
    name: "encrypt_object",
    title: "Request encryption at rest",
    description: "Ask that an object be encrypted at rest, with an algorithm the server offers.",
    arguments: [uriArgument, {
      name: "algorithm",
      description: 'The algorithm, mode and key length, as the cdmi_encryption capability ' +
        'gives them, for example "AES_CBC_256".',
      required: false,
    }],
    summary: (a) => `Request encryption at rest for ${a.uri}`,
    reads: (a) => [`${a.uri}?metadata`, "/cdmi_capabilities/dataobject/"],
    text: (a) =>
      `Request that the object at ${a.uri} be encrypted at rest` +
      `${a.algorithm ? `, using ${a.algorithm}` : ""}.\n\n` +
      "Observe the following:\n\n" +
      "1. Read the cdmi_encryption capability FIRST and use one of the values it contains. " +
      "The item is not free text: an algorithm, mode and length the server does not offer is " +
      "refused, and a guess that happens to be refused tells the caller nothing about what is " +
      "available. The capabilities are given below.\n" +
      "2. cdmi_encryption is a REQUEST, not a statement of fact. What is actually in force is " +
      "reported by cdmi_encryption_provided. After the update, read that item back — if it is " +
      "absent or differs from what was asked for, the object is not encrypted the way the " +
      "caller believes, and you must say so plainly.\n" +
      "3. Setting the item on an object that already holds a value does not necessarily " +
      "encrypt the octets already stored. Say what you have confirmed and what you have not.\n" +
      "4. Do not report the object as encrypted on the strength of the update having " +
      "succeeded. The update records a request; the provided item records the outcome.\n\n" +
      "Send one cdmi_update whose mode is replace-fields and whose uri selects " +
      "metadata=cdmi_encryption, then read metadata=cdmi_encryption_provided back.",
  },
];

/** The list a prompts/list call returns: what a client shows and offers. */
export function promptList(): Record<string, unknown>[] {
  return PROMPTS.map((p) => ({
    name: p.name,
    title: p.title,
    description: p.description,
    arguments: p.arguments,
  }));
}

/**
 * The messages a prompts/get call returns.
 *
 * The instructions come first, as one user message, and the current state of
 * each object the prompt reads follows as an embedded resource block — "embedded
 * resources enable prompts to seamlessly incorporate server-managed content ...
 * directly into the conversation flow". A prompt that edits a structured field
 * is thereby editing from fact rather than from a guess, which is the difference
 * between appending an access control entry and replacing the list.
 *
 * A read that fails is omitted rather than reported as a failure of the prompt:
 * the object may not be there yet — provision_home runs before its container
 * exists — and a prompt whose expansion depends on an object existing would be
 * unusable for the job it is for. What the model is told to do does not change.
 */
export async function promptMessages(prompt: Prompt, args: Record<string, string>,
  read: (uri: string) => Promise<Record<string, unknown> | undefined>):
  Promise<Record<string, unknown>[]> {
  const messages: Record<string, unknown>[] = [
    { role: "user", content: { type: "text", text: prompt.text(args) } },
  ];
  for (const uri of prompt.reads?.(args) ?? []) {
    const resource = await read(uri);
    if (resource === undefined) continue;
    messages.push({ role: "user", content: { type: "resource", resource } });
  }
  return messages;
}

/**
 * The arguments of a call against those the prompt declares. "Invalid prompt
 * name: -32602 (Invalid params); Missing required arguments: -32602", and
 * "servers SHOULD validate prompt arguments before processing".
 */
export function checkPromptArguments(prompt: Prompt, args: Record<string, unknown>):
  string | undefined {
  for (const [k, v] of Object.entries(args)) {
    if (!prompt.arguments.some((a) => a.name === k)) {
      return `the ${prompt.name} prompt takes no argument named ${JSON.stringify(k)}; it takes ` +
        prompt.arguments.map((a) => a.name).join(", ");
    }
    if (typeof v !== "string") {
      return `the ${k} argument of the ${prompt.name} prompt holds a JSON string`;
    }
  }
  for (const a of prompt.arguments) {
    if (a.required && typeof args[a.name] !== "string") {
      return `the ${a.name} argument is required by the ${prompt.name} prompt and was not supplied`;
    }
  }
  return undefined;
}
