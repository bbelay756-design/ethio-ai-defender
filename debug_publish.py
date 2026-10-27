"""Debug the publish_rule_version function - fixed version."""
import sys, os
sys.path.insert(0, r'C:\Users\MILKWAY\ethio-ai-defender')

from datetime import datetime, timezone
from app.db.models import Base, YaraRuleModel, YaraRuleVersionModel
from app.db.session import Base as Base2, SessionLocal, create_engine
from tests.test_yara_rule_versioning import make_fk_engine
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
from hashlib import sha256

engine = make_fk_engine("sqlite:///:memory:")
Base2.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

rule = YaraRuleModel(name="Debug_Rule", namespace="ns_debug", source="rule Debug { true }", version=1, is_active=True)
db.add(rule)
db.commit()
db.refresh(rule)
print(f"Rule ID: {rule.id}")

# Try the nested transaction approach
try:
    print("\n--- Attempt with begin_nested ---")
    with db.begin_nested():
        print("  inside begin_nested")
        # Lock the rule row
        ruledb = db.query(YaraRuleModel).filter(YaraRuleModel.id == rule.id).with_for_update().first()
        print(f"  locked rule: {ruledb.name}")
        
        # Check max version
        max_result = db.execute(
            text("SELECT MAX(version) FROM yara_rule_versions WHERE rule_id = :rid"),
            {"rid": ruledb.id},
        ).scalar()
        print(f"  max version: {max_result}")
        
        next_version = (max_result or 0) + 1
        print(f"  next_version: {next_version}")
        
        # Compute SHA-256
        source_hash = sha256("rule Debug { true }".encode("utf-8")).hexdigest()
        print(f"  source_hash: {source_hash[:16]}...")
        
        # Create version - do NOT set published_at manually; model has default
        new_version = YaraRuleVersionModel(
            rule_id=ruledb.id,
            version=next_version,
            source="rule Debug { true }",
            source_hash=source_hash,
            description="Debug desc",
            author="debug_author",
            # published_at will use model default (datetime.now timez.utc)
        )
        db.add(new_version)
        print(f"  added version: id={new_version.id}")
        
        # Update rule pointer
        ruledb.current_version_id = new_version.id
        print(f"  set current_version_id = {ruledb.current_version_id}")
        
        db.flush()
        print("  flushed")
        print(f"  new_version.published_at={new_version.published_at}")
        
        # Try commit
        try:
            db.commit()
            print("  commit SUCCESS")
            print(f"  version.id={new_version.id}, version={new_version.version}")
            print(f"  rule.current_version_id={rule.current_version_id}")
            print(f"  rule.current_version.source={rule.current_version.source if rule.current_version else None}")
        except Exception as e:
            print(f"  commit FAILED: {e}")
            db.rollback()
            print("  rolled back")

except Exception as e:
    print(f"  outer exception: {e}")
    import traceback
    traceback.print_exc()

db.close()
print("\ndone")