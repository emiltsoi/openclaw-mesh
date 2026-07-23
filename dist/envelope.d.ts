export interface A2AEnvelope {
    from: string;
    to: string;
    id: string;
    action: "do" | "info";
    reply: "yes" | "no";
}
export declare function parseA2AEnvelope(text: string): A2AEnvelope | null;
export declare function stripEnvelope(text: string): string;
