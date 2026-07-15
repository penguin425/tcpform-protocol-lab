/* tcpform analysis worker: keeps large trace queries and diffs off the UI thread. */
'use strict';
importScripts('workbench-tools.js', 'packet-view.js');

self.onmessage = event => {
  const { id, operation, payload } = event.data || {};
  try {
    let result;
    if (operation === 'query') {
      result = self.tcpformWorkbench.executeQuery(
        payload.events || [],
        payload.query || '',
        self.tcpformDecodePacket,
      );
    } else if (operation === 'diff') {
      result = self.tcpformWorkbench.detailedDiff(
        payload.left || [],
        payload.right || [],
        self.tcpformDecodePacket,
        payload.options || {},
      );
    } else {
      throw new Error(`unknown worker operation ${operation}`);
    }
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({
      id,
      error: { message: error.message, position: error.position ?? null },
    });
  }
};
