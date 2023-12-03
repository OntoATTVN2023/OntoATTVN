import os
from owlready2 import *


def main():

    # Get the directory of the current script
    script_directory = os.path.dirname(os.path.realpath(__file__))

    # Set onto_path to the script directory
    onto_path.append(script_directory)

    # Get ontology
    onto = get_ontology("http://test.org/Ontology.owl")

    # Initialize class
    with onto:

        class Tactic(Thing):
            pass

        class Technique(Thing):
            pass

        class Defense(Thing):
            pass

        class Deceive(Defense):
            pass

        class Model(Defense):
            pass

        class Harden(Defense):
            pass

        class Detect(Defense):
            pass

        class Isolate(Defense):
            pass

        class Evict(Defense):
            pass

        class Restore(Defense):
            pass

        class Mitigation(Thing):
            pass

        class Detection(Thing):
            pass

        class CAPEC(Thing):
            pass

        class CWE(Thing):
            pass

        #  Initialize Data properties

        class hasID(DataProperty):
            range = [str]

        class hasName(DataProperty):
            range = [str]

        class hasDescription(DataProperty):
            range = [str]

        class hasName(DataProperty):
            range = [str]

        class hasMitigation(DataProperty):
            domain = [Technique]
            range = [str]

        class hasDetection(DataProperty):
            domain = [Technique]
            range = [str]

        class hasType(DataProperty):
            domain = [Deceive, Model, Harden, Detect, Isolate, Evict, Restore]
            range = [str]

        #  Initialize Object properties
        class isSubTechniqueOf(ObjectProperty):
            domain = [Technique]
            range = [Technique]

        class isSubDeceiveOf(ObjectProperty):
            domain = [Deceive]
            range = [Deceive]

        class isSubModelOf(ObjectProperty):
            domain = [Model]
            range = [Model]

        class isSubHardenOf(ObjectProperty):
            domain = [Harden]
            range = [Harden]

        class isSubDetectOf(ObjectProperty):
            domain = [Detect]
            range = [Detect]

        class isSubIsolateOf(ObjectProperty):
            domain = [Isolate]
            range = [Isolate]

        class isSubEvictOf(ObjectProperty):
            domain = [Evict]
            range = [Evict]

        class isSubRestoreOf(ObjectProperty):
            domain = [Restore]
            range = [Restore]

        class isSubDetectionOf(ObjectProperty):
            domain = [Detection]
            range = [Detection]

        class accomplishedTactic(ObjectProperty):
            domain = [Technique]
            range = [Tactic]

        class preventedBy(ObjectProperty):
            domain = [Technique]
            range = [Mitigation]

        class identifiedBy(ObjectProperty):
            domain = [Technique]
            range = [Detection]

        class hasDefense(ObjectProperty):
            domain = [Technique]
            range = [Defense]

        class mayBeDetectedBy(ObjectProperty):
            domain = [Technique]
            range = [Detect]

        class mayBeIsolatedBy(ObjectProperty):
            domain = [Technique]
            range = [Isolate]

        class mayBeDeceivedBy(ObjectProperty):
            domain = [Technique]
            range = [Deceive]

        class mayBeModeledBy(ObjectProperty):
            domain = [Technique]
            range = [Model]

        class mayBeEvictedBy(ObjectProperty):
            domain = [Technique]
            range = [Evict]

        class mayBeHardenedBy(ObjectProperty):
            domain = [Technique]
            range = [Harden]

        class mayBeRestoredBy(ObjectProperty):
            domain = [Technique]
            range = [Restore]

        class mapToCAPEC(ObjectProperty):
            domain = [CAPEC]
            range = [Technique]

        class hasCAPEC(ObjectProperty):
            domain = [CWE]
            range = [CAPEC]

        class isParentOfCAPEC(ObjectProperty):
            domain = [CAPEC]
            range = [CAPEC]

        class isCanPrecedeCAPEC(ObjectProperty):
            domain = [CAPEC]
            range = [CAPEC]

        class isCanFollowCAPEC(ObjectProperty):
            domain = [CAPEC]
            range = [CAPEC]

        class isChildOfCAPEC(ObjectProperty):
            domain = [CAPEC]
            range = [CAPEC]

        class isPeerOfCAPEC(ObjectProperty):
            domain = [CAPEC]
            range = [CAPEC]

        class isParentOfCWE(ObjectProperty):
            domain = [CWE]
            range = [CWE]

        class isCanPrecedeCWE(ObjectProperty):
            domain = [CWE]
            range = [CWE]

        class isCanFollowCWE(ObjectProperty):
            domain = [CWE]
            range = [CWE]

        class isChildOfCWE(ObjectProperty):
            domain = [CWE]
            range = [CWE]

        class isPeerOfCWE(ObjectProperty):
            domain = [CWE]
            range = [CWE]

        class isMemberOfCWE(ObjectProperty):
            domain = [CWE]
            range = [CWE]

        class isCanAlsoBeCWE(ObjectProperty):
            domain = [CWE]
            range = [CWE]

        class isSubDetectionOf(ObjectProperty):
            domain = [Detection]
            range = [Detection]

    exec(open("initialize_tactics.py").read())

    exec(open("initialize_techniques.py").read())

    exec(open("initialize_detections.py").read())

    exec(open("initialize_mitigations.py").read())

    exec(open("initialize_defenses.py").read())

    exec(open("initialize_capec.py").read())

    exec(open("initialize_cwe.py").read())

    exec(open("asserted_properties_technique_tactic.py").read())

    exec(open("asserted_properties_technique_mitigation.py").read())

    exec(open("asserted_properties_technique_detection.py").read())

    exec(open("asserted_properties_technique_defense.py").read())

    exec(open("asserted_properties_capec_technique.py").read())

    exec(open("asserted_properties_cwe_capec.py").read())

    exec(open("asserted_properties_cwe_capec.py").read())

    # Lưu ontology
    onto.save()

if __name__ == "__main__":
    main()
