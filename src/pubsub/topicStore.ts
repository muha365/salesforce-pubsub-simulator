import { ReplaySubject, firstValueFrom, from } from "rxjs";
import { skip, take, toArray } from "rxjs/operators";

export interface SchemaInfo {
  schema_id?: string;
  schema_version?: string;
}

export interface EventEnvelope {
  replayId: Buffer;
  payload: Buffer;
}

export interface TopicSnapshot {
  schemaInfo: SchemaInfo | null;
  events: EventEnvelope[];
}

export class TopicStore {
  private readonly events: EventEnvelope[] = [];
  private readonly stream = new ReplaySubject<EventEnvelope>(Number.POSITIVE_INFINITY);
  private replayCounter = 0;
  private schemaInfo: SchemaInfo | null;

  constructor(initialSchemaInfo: SchemaInfo | null = null) {
    this.schemaInfo = initialSchemaInfo;
  }

  nextReplayId(): number {
    return this.replayCounter++;
  }

  append(event: EventEnvelope): void {
    this.events.push(event);
    this.stream.next(event);
  }

  updateSchemaInfo(schemaInfo: SchemaInfo | null | undefined): void {
    if (schemaInfo) {
      this.schemaInfo = schemaInfo;
    }
  }

  getSchemaInfo(): SchemaInfo | null {
    return this.schemaInfo;
  }

  async slice(startIndex: number, count?: number): Promise<EventEnvelope[]> {
    const effectiveCount = typeof count === "number" && count >= 0 ? count : this.events.length;
    if (effectiveCount === 0) {
      return [];
    }

    return firstValueFrom(
      from(this.events).pipe(
        skip(startIndex),
        take(effectiveCount),
        toArray(),
      ),
    );
  }

  snapshot(): TopicSnapshot {
    return {
      schemaInfo: this.schemaInfo,
      events: [...this.events],
    };
  }

  findReplayIndex(replayId: Buffer): number {
    const key = replayId.toString("base64");
    return this.events.findIndex((event) => event.replayId.toString("base64") === key);
  }
}
