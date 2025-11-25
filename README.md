# COS457-Teaching-Project | Database Privacy & Privacy-Preserving Technologies

An exploration of privacy-preserving techniques in modern database systems for USM COS 457

## Team

- **Aubin Mugisha**
- **Nikki Gorski**
- **Sarah Kayembe**
- **Yunlong Li**
- **Kristina Zbinden**

---

## Database privacy overview

- Modern databases handle highly sensitive data in healthcare, finance, and tech, so privacy is critical for trust and regulatory compliance (HIPAA, GDPR, CCPA).
- Classic tools like access control (RBAC, DAC, ABAC) and encryption at rest/in transit protect stored and transmitted data, but often expose plaintext during queries and analytics.

## Key Takeaways

### 1. **From classic security to privacy-preserving tech**

- Early database security relied on physical protection, basic authentication, and formal access control models, later adding strong encryption, logging, and intrusion detection.
- Massive breaches and SQL injection attacks showed that perimeter defenses alone are not enough, pushing systems toward techniques that limit what any single party can see.

### 2. **Key privacy-preserving techniques**

- Homomorphic encryption, differential privacy, and secure multi-party computation allow computation or statistics without exposing raw individual records.
- Trusted execution environments, federated learning, and synthetic data let organizations train models and share patterns while keeping raw data local or replaced with realistic fakes.

### 3. **Concrete mechanisms and examples**

- Zero-knowledge proofs and commitments let users prove properties (like “score ≥ 700” or “balance ≥ threshold”) without revealing exact values.
- Real-world deployments include Apple’s use of differential privacy, privacy-preserving fraud detection across banks, and healthcare systems that combine encryption, RBAC, DLP, and cloud protections.

### 4. **Impact and open challenges**

- Privacy-preserving analytics aim to use data productively while reducing trust in any single server and limiting damage from breaches.
- Open challenges include quantum threats to encryption, regulatory complexity, AI opacity and bias, and balancing surveillance or analytic needs with ethical data use.

### Topics Covered

- Database security evolution from the 1960s to modern cloud architectures
- Access control models: DAC, MAC, RBAC, and ABAC
- Classic encryption techniques and their limitations
- Differential privacy and noise calibration
- Zero-knowledge proofs for data verification
- Federated learning without centralized data
- Secure multi-party computation for collaborative analytics
- Synthetic data generation and anonymization
- Cloud database protection strategies
- Privacy challenges in AI and quantum computing threats

---

## Resources

For the full presentation slidedeck, see the attached materials in this repository.

---

**Course:** COS 457 – Database Systems  

**Professor:** Dr. Behrooz Mansouri

**Institution:** University of Southern Maine  

**Date:** November 2025
