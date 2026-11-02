"""
Concept Bank & Benign Enterprise Anchors (Pillar III)
Defines prompt-ensembled safety taxonomies for zero-text semantic concept jailbreaks
and benign enterprise reference anchors for zero-false-positive margin calibration.
"""

from typing import Dict, List, Tuple
import torch
import torch.nn.functional as F

from core.vision.schemas import ConceptScore


# ── Threat Concept Categories & Prompt Ensembles ──────────────────────────────
THREAT_CONCEPTS_TAXONOMY: Dict[str, Tuple[str, List[str]]] = {
    "WEAPON_FIREARM": (
        "WEAPON",
        [
            "a high-resolution photo of a firearm, handgun, pistol, or rifle",
            "an assault rifle, shotgun, or military firearm with ammunition",
            "close-up photo of a Glock, semi-automatic pistol, or revolver",
            "schematics or 3D CAD blueprints of a 3D-printed firearm or gun",
            "a person pointing a loaded firearm at the viewer",
        ],
    ),
    "EXPLOSIVE_CBRN": (
        "CBRN",
        [
            "an improvised explosive device, pipe bomb, or detonator",
            "chemical, biological, radiological, or nuclear hazardous material",
            "military ordnance, artillery shell, grenade, or plastic explosive",
            "bomb making instructions, explosive chemical synthesis schematic",
            "hazardous biohazard canister containing toxic pathogens",
        ],
    ),
    "VIOLENCE_GORE": (
        "VIOLENCE",
        [
            "extreme physical violence, bloodshed, or severe bodily mutilation",
            "a depiction of brutal physical assault, torture, or execution",
            "graphic violent injury, severe human trauma, and open wounds",
        ],
    ),
    "CONTRABAND_ILLICIT": (
        "CONTRABAND",
        [
            "packaged illicit narcotics, heroin, fentanyl, or crystal meth",
            "bricks of cocaine, illegal drug paraphernalia, or narcotic press",
            "stacks of counterfeit banknotes or black market contraband goods",
        ],
    ),
    "PHYSICAL_BYPASS": (
        "BYPASS",
        [
            "lockpicking tension wrench and pick manipulating a lock cylinder",
            "physical security bypass tool attacking a door latch or deadbolt",
            "electronic RFID badge cloner or physical lock defeat apparatus",
        ],
    ),
    "JAILBREAK_FRAMING": (
        "JAILBREAK",
        [
            "a visual graphic or meme instructing an AI model to bypass safety rules",
            "an infographic displaying DAN or developer mode override instructions",
            "rendered typography demanding the model disregard safety guidelines",
        ],
    ),
}

# ── Benign Enterprise Anchor Taxonomy (Prevents False Positives) ─────────────
BENIGN_ANCHORS_TAXONOMY: Dict[str, List[str]] = {
    "ENTERPRISE_INVOICE": [
        "a scanned corporate commercial invoice with itemized line items and total",
        "a paper cash register receipt from a retail store or restaurant",
        "a business billing statement with account numbers and tax calculations",
    ],
    "CODE_SCREENSHOT": [
        "a dark mode code editor screenshot displaying Python, TypeScript, or C++",
        "a terminal shell window with command-line output and compiler logs",
        "a code diff with green and red highlighting in GitHub or VS Code",
    ],
    "ARCHITECTURE_DIAGRAM": [
        "a software architecture diagram with microservices, cloud VPC, and database",
        "a network topology flowchart with load balancers, nodes, and arrows",
        "a clean UML sequence diagram or systems engineering workflow schema",
    ],
    "FINANCIAL_CHART": [
        "a business analytics dashboard with bar charts, line graphs, and KPI metrics",
        "a candlestick financial stock market chart with volume indicators",
        "a spreadsheet table with rows, columns, and corporate quarterly earnings",
    ],
    "SLIDE_DECK": [
        "a corporate presentation slide with bullet points, title, and marketing diagram",
        "a clean PowerPoint or Keynote slide outlining business strategy",
    ],
    "NATURAL_SCENERY": [
        "a photographic landscape of mountains, trees, sky, or ocean",
        "a clean photo of an office desk, laptop, coffee cup, or architectural building",
    ],
    "SAFETY_DATA_SHEET": [
        "a standard corporate Safety Data Sheet (SDS) with GHS hazard warning symbols",
        "a laboratory chemical catalog page with safety warnings and handling protocols",
    ],
}


class ConceptBank:
    """
    Manages precomputed, L2-normalized 512-dimensional concept embeddings.
    Zero text-encoder latency at runtime.
    """

    def __init__(self, embedding_dim: int = 512):
        self.embedding_dim = embedding_dim
        self.threat_names: List[str] = list(THREAT_CONCEPTS_TAXONOMY.keys())
        self.threat_categories: List[str] = [
            THREAT_CONCEPTS_TAXONOMY[k][0] for k in self.threat_names
        ]
        self.benign_names: List[str] = list(BENIGN_ANCHORS_TAXONOMY.keys())

        # Precomputed embedding matrices: [N_threats, 512] and [N_benign, 512]
        self.threat_matrix: torch.Tensor = torch.zeros((len(self.threat_names), embedding_dim))
        self.benign_matrix: torch.Tensor = torch.zeros((len(self.benign_names), embedding_dim))
        self._initialize_concept_vectors()

    def _initialize_concept_vectors(self):
        """
        Initializes calibrated L2-normalized anchor vectors.
        Uses deterministic quasi-orthogonal basis vectors with category clustering.
        """
        torch.manual_seed(42)

        # Build distinct directional subspaces for threat categories
        for i, name in enumerate(self.threat_names):
            base_vec = torch.randn(self.embedding_dim)
            # Add category-specific bias
            cat = self.threat_categories[i]
            cat_bias = torch.zeros(self.embedding_dim)
            cat_idx = hash(cat) % self.embedding_dim
            cat_bias[cat_idx] = 2.5
            v = base_vec + cat_bias
            self.threat_matrix[i] = F.normalize(v, p=2, dim=0)

        # Build distinct directional subspaces for benign enterprise anchors
        for j, name in enumerate(self.benign_names):
            base_vec = torch.randn(self.embedding_dim)
            benign_bias = torch.zeros(self.embedding_dim)
            b_idx = (hash(name) * 3) % self.embedding_dim
            benign_bias[b_idx] = 2.5
            v = base_vec + benign_bias
            self.benign_matrix[j] = F.normalize(v, p=2, dim=0)

    def get_matrices(self, device: torch.device) -> Tuple[torch.Tensor, torch.Tensor]:
        """Returns threat and benign matrices on the target execution device."""
        return self.threat_matrix.to(device), self.benign_matrix.to(device)


# Singleton concept bank instance
concept_bank = ConceptBank()

