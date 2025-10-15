# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Batch processing state management for interactive audit workflows."""

import json
import time
import uuid
from datetime import datetime, timezone
from loguru import logger
from typing import Any, Dict, List, Optional


# Constants
DEFAULT_BATCH_SIZE = 5
BATCH_SESSION_TIMEOUT = 3600  # 1 hour


class BatchProcessingState:
    """Manages state for interactive batch processing of audit targets."""
    
    def __init__(self, input_obj: Dict[str, Any], region: str, banner: str):
        self.input_obj = input_obj
        self.region = region
        self.banner = banner
        self.target_batches = self._create_batches()
        self.current_batch_idx = 0
        self.processed_results: List[Dict[str, Any]] = []
        self.failed_batches: List[Dict[str, Any]] = []
        self.created_at = time.time()
        self.last_activity = time.time()
        
    def _create_batches(self) -> List[List[Dict[str, Any]]]:
        """Split targets into batches."""
        targets = self.input_obj.get('AuditTargets', [])
        batch_size = DEFAULT_BATCH_SIZE
        
        if len(targets) <= batch_size:
            return [targets] if targets else []
            
        batches = []
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            batches.append(batch)
            
        logger.info(f'Created {len(batches)} batches from {len(targets)} targets')
        return batches
    
    def has_more_batches(self) -> bool:
        """Check if there are more batches to process."""
        return self.current_batch_idx < len(self.target_batches)
    
    def get_next_batch(self) -> Optional[List[Dict[str, Any]]]:
        """Get the next batch of targets to process."""
        if self.has_more_batches():
            batch = self.target_batches[self.current_batch_idx]
            self.current_batch_idx += 1
            self.last_activity = time.time()
            return batch
        return None
    
    def add_batch_result(self, result: Dict[str, Any]) -> None:
        """Add a batch result to the processed results."""
        self.processed_results.append(result)
        self.last_activity = time.time()
        
        if "BatchError" in result:
            self.failed_batches.append(result)
    
    def get_progress_summary(self) -> Dict[str, Any]:
        """Get current progress summary."""
        total_findings = 0
        for result in self.processed_results:
            if "AuditFindings" in result:
                total_findings += len(result["AuditFindings"])
                
        return {
            "total_batches": len(self.target_batches),
            "processed_batches": len(self.processed_results),
            "remaining_batches": len(self.target_batches) - len(self.processed_results),
            "successful_batches": len(self.processed_results) - len(self.failed_batches),
            "failed_batches": len(self.failed_batches),
            "total_findings": total_findings,
            "has_more": self.has_more_batches()
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary for serialization."""
        return {
            "input_obj": self.input_obj,
            "region": self.region,
            "banner": self.banner,
            "target_batches": self.target_batches,
            "current_batch_idx": self.current_batch_idx,
            "processed_results": self.processed_results,
            "failed_batches": self.failed_batches,
            "created_at": self.created_at,
            "last_activity": self.last_activity
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BatchProcessingState':
        """Create state from dictionary."""
        state = cls(data["input_obj"], data["region"], data["banner"])
        state.target_batches = data["target_batches"]
        state.current_batch_idx = data["current_batch_idx"]
        state.processed_results = data["processed_results"]
        state.failed_batches = data["failed_batches"]
        state.created_at = data["created_at"]
        state.last_activity = data["last_activity"]
        return state


# Global state storage for active batch processing sessions
ACTIVE_BATCH_SESSIONS: Dict[str, BatchProcessingState] = {}


def store_batch_state(state: BatchProcessingState) -> str:
    """Store batch state and return session ID."""
    session_id = f"batch_{uuid.uuid4().hex[:8]}"
    ACTIVE_BATCH_SESSIONS[session_id] = state
    logger.info(f'Created batch session {session_id} with {len(state.target_batches)} batches')
    return session_id


def get_batch_state(session_id: str) -> Optional[BatchProcessingState]:
    """Retrieve batch state by session ID."""
    state = ACTIVE_BATCH_SESSIONS.get(session_id)
    if state:
        state.last_activity = time.time()
    return state


def cleanup_session(session_id: str) -> bool:
    """Remove a batch session."""
    if session_id in ACTIVE_BATCH_SESSIONS:
        del ACTIVE_BATCH_SESSIONS[session_id]
        logger.info(f'Cleaned up batch session {session_id}')
        return True
    return False


def cleanup_expired_sessions() -> int:
    """Clean up expired batch sessions."""
    current_time = time.time()
    expired_sessions = [
        session_id for session_id, state in ACTIVE_BATCH_SESSIONS.items()
        if current_time - state.last_activity > BATCH_SESSION_TIMEOUT
    ]
    
    for session_id in expired_sessions:
        del ACTIVE_BATCH_SESSIONS[session_id]
        
    if expired_sessions:
        logger.info(f'Cleaned up {len(expired_sessions)} expired batch sessions')
        
    return len(expired_sessions)


def get_active_sessions_count() -> int:
    """Get count of active batch sessions."""
    cleanup_expired_sessions()  # Clean up first
    return len(ACTIVE_BATCH_SESSIONS)


def format_batch_response_string(
    batch_result: Dict[str, Any], 
    state: BatchProcessingState, 
    session_id: str
) -> str:
    """Format a single batch result as a user-friendly string."""
    progress = state.get_progress_summary()
    
    # Handle batch errors
    if "BatchError" in batch_result:
        error_info = batch_result["BatchError"]
        response = f"""{state.banner}
❌ BATCH {error_info['batch_index']}/{progress['total_batches']} FAILED
🚨 Error: {error_info['error_message']}
📊 Progress: {progress['processed_batches']}/{progress['total_batches']} batches processed

---- BATCH ERROR DETAILS ----
{json.dumps(batch_result, indent=2, default=str)}
---- END ERROR DETAILS ----

"""
    else:
        # Successful batch
        findings_count = len(batch_result.get('AuditFindings', []))
        batch_metadata = batch_result.get('BatchMetadata', {})
        
        response = f"""{state.banner}
📦 BATCH {batch_metadata.get('batch_index', '?')}/{progress['total_batches']} COMPLETED
🔍 Found {findings_count} findings in this batch
📊 Progress: {progress['processed_batches']}/{progress['total_batches']} batches processed
📈 Total findings so far: {progress['total_findings']}

---- BATCH RESULTS ----
{json.dumps(batch_result, indent=2, default=str)}
---- END BATCH RESULTS ----

"""
    
    # Add next steps
    if progress['has_more']:
        response += f"""🔄 NEXT STEPS:
- Continue with next batch: continue_audit_batch(batch_session_id="{session_id}")
- Get final aggregated results: finalize_audit_session(batch_session_id="{session_id}")
- Check status: get_batch_status(batch_session_id="{session_id}")

⚠️ Session ID: {session_id} (save this for continuation)
"""
    else:
        response += f"""✅ ALL BATCHES COMPLETED
📊 Final Summary: {progress['successful_batches']} successful, {progress['failed_batches']} failed
Use finalize_audit_session(batch_session_id="{session_id}") to get aggregated results from all batches.

⚠️ Session ID: {session_id}
"""
    
    return response


def format_final_results_string(
    final_result: Dict[str, Any], 
    state: BatchProcessingState
) -> str:
    """Format final aggregated results as a user-friendly string."""
    batch_summary = final_result.get('BatchSummary', {})
    
    response = f"""{state.banner}
✅ FINAL AGGREGATED RESULTS - ALL BATCHES COMPLETED

📊 BATCH PROCESSING SUMMARY:
- Total Batches: {batch_summary.get('TotalBatches', 0)}
- Successful Batches: {batch_summary.get('SuccessfulBatches', 0)}
- Failed Batches: {batch_summary.get('FailedBatches', 0)}
- Total Targets Processed: {batch_summary.get('TotalTargetsProcessed', 0)}
- Total Findings: {batch_summary.get('TotalFindingsCount', 0)}

---- AGGREGATED FINDINGS ----
{json.dumps(final_result, indent=2, default=str)}
---- END RESULTS ----
"""
    
    if batch_summary.get('FailedBatches', 0) > 0:
        response += f"""
⚠️ Note: {batch_summary['FailedBatches']} batch(es) failed during processing.
Check the individual batch results for error details.
"""
    
    return response
