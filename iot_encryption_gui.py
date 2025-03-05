import tkinter as tk
from tkinter import ttk, scrolledtext
import random
from gmpy2 import mpz, powmod, next_prime, invert
from threading import Thread

# ------------------------------------------------------------------
# 1) TRANSACTIONAL NODE AND COLLABORATIVE ENCRYPTION SYSTEM CLASSES
#    (Supporting "RSA Only" or "Hybrid (RSA+ElGamal)" mode)
# ------------------------------------------------------------------

class TransactionalNode:
    """Represents an IoT node with RSA and optional ElGamal parameters."""
    def __init__(self, node_type, position=None):
        self.node_type = node_type
        self.position = position

        # RSA-style parameters
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.r = None
        self.k = None  # Nested RSA portion

        # ElGamal parameters (only used in Hybrid mode)
        self.x = None  # Secret exponent
        self.y = None  # Public y = g^x mod p_g

    def initialize_rsa(self, bit_length):
        """Generate RSA primes and set up n, phi(n), and random offset r."""
        self.p = next_prime(mpz(random.getrandbits(bit_length)))
        self.q = next_prime(mpz(random.getrandbits(bit_length)))
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.r = mpz(random.randint(2**32, 2**64))

    def compute_rsa_key_contribution(self, previous_key=None):
        """
        Each node extends the 'nested' RSA key:
          k_i = (k_(i-1) * phi(n_i)) + r_i
        If previous_key is None, this node is the first (Destination).
        """
        if previous_key is None:
            self.k = self.phi + self.r
        else:
            self.k = (previous_key * self.phi) + self.r
        return self.k

    def initialize_elgamal(self, p_g, g):
        """Generate ElGamal exponent x and public y = g^x mod p_g."""
        self.x = mpz(random.randint(2, max(3, p_g - 2)))
        self.y = powmod(g, self.x, p_g)


class CollaborativeEncryptionSystem:
    """
    Creates a multi-party encryption scheme with:
      - Destination node
      - Some number of intermediate nodes
      - Source node
    And supports either:
      (A) RSA-Only mode
      (B) Hybrid RSA + ElGamal
    """
    def __init__(self, num_intermediates=3, prime_bits=128, mode="Hybrid", logger=None):
        """
        :param num_intermediates: # of intermediate nodes
        :param prime_bits: RSA prime bit-length
        :param mode: "RSA" or "Hybrid"
        :param logger: function to call for logging (string output)
        """
        self.num_intermediates = num_intermediates
        self.prime_bits = prime_bits
        self.mode = mode  # "RSA" or "Hybrid"
        self.logger = logger if logger else print

        # Node creation
        self.destination = TransactionalNode("Destination", "D")
        self.intermediates = [
            TransactionalNode("Intermediate", f"I{i+1}")
            for i in range(num_intermediates)
        ]
        self.source = TransactionalNode("Source", "S")

        # Build RSA portion (always used, even in Hybrid)
        self._log(f">>> Building {mode} system with {num_intermediates} nodes at {prime_bits} bits <<<")
        self._initialize_rsa_all_nodes()
        self.collaborative_key = self._build_rsa_collaborative_key()
        self.global_modulus = self._compute_global_modulus()

        # If Hybrid, build ElGamal portion
        if self.mode == "Hybrid":
            self._log("\n-- Hybrid Mode: Initializing ElGamal --")
            self.p_g, self.g = self._generate_elgamal_params(prime_bits)
            self._initialize_elgamal_all_nodes()
            self.elgamal_public = self._build_elgamal_collab_key()
        else:
            self._log("\n-- RSA-Only Mode: Skipping ElGamal initialization --")
            self.p_g = None
            self.g = None
            self.elgamal_public = None

    def _log(self, msg):
        self.logger(msg)

    # ----------------- RSA Core Steps ------------------
    def _initialize_rsa_all_nodes(self):
        """Create RSA primes/params for the Destination, Intermediates, and Source."""
        self._log("\n[1] RSA Initialization")
        # Destination
        self.destination.initialize_rsa(self.prime_bits)
        self._log(f"  Destination => n={self.destination.n}, phi={self.destination.phi}, r={self.destination.r}")
        # Intermediates
        for i, node in enumerate(self.intermediates):
            node.initialize_rsa(self.prime_bits)
            self._log(f"  Intermediate I{i+1} => n={node.n}, phi={node.phi}, r={node.r}")
        # Source
        self.source.initialize_rsa(self.prime_bits)
        self._log(f"  Source => n={self.source.n}, phi={self.source.phi}, r={self.source.r}")

    def _build_rsa_collaborative_key(self):
        """Nested key building from Destination -> Intermediates -> Source (+1 at end)."""
        self._log("\n[2] Building Nested RSA Key")
        current_key = self.destination.compute_rsa_key_contribution(None)
        self._log(f"  Destination partial key = {current_key}")

        for i, node in enumerate(self.intermediates):
            current_key = node.compute_rsa_key_contribution(current_key)
            self._log(f"  Inter. I{i+1} partial key = {current_key}")

        final_key = (current_key * self.source.phi) + 1
        self._log(f"  Source => final RSA key = {final_key}")
        return final_key

    def _compute_global_modulus(self):
        """Product of n-values from all nodes => global RSA modulus."""
        self._log("\n[3] Computing Global RSA Modulus")
        gm = mpz(1)
        # Destination
        gm *= self.destination.n
        # Intermediates
        for node in self.intermediates:
            gm *= node.n
        # Source
        gm *= self.source.n
        self._log(f"  Global Modulus = {gm}")
        return gm

    # ----------------- ElGamal for Hybrid -------------
    def _generate_elgamal_params(self, bit_length):
        """
        Single large prime p_g for the group, generator g=2 (simple).
        In practice, you'd use a safe prime or known generator.
        """
        self._log("\n     [ElGamal Setup]")
        p_g = next_prime(mpz(random.getrandbits(bit_length+2)))
        g = mpz(2)
        self._log(f"       p_g = {p_g}")
        self._log(f"       g   = {g}")
        return p_g, g

    def _initialize_elgamal_all_nodes(self):
        """Each node picks x, y = g^x mod p_g."""
        self._log("\n     [Init ElGamal for All Nodes]")
        self.destination.initialize_elgamal(self.p_g, self.g)
        self._log(f"       D => x={self.destination.x}, y={self.destination.y}")
        for i, node in enumerate(self.intermediates):
            node.initialize_elgamal(self.p_g, self.g)
            self._log(f"       I{i+1} => x={node.x}, y={node.y}")
        self.source.initialize_elgamal(self.p_g, self.g)
        self._log(f"       S => x={self.source.x}, y={self.source.y}")

    def _build_elgamal_collab_key(self):
        """Multiply all y_i => collaborative Y (public)."""
        self._log("\n     [Build ElGamal Collab Key]")
        y_total = mpz(1)
        for node in [self.destination] + self.intermediates + [self.source]:
            y_total = (y_total * node.y) % self.p_g
        self._log(f"       Y_total = {y_total}")
        return y_total

    # ---------------- ENCRYPT / DECRYPT ---------------
    def encrypt_message(self, message):
        """
        Encrypt using nested RSA + optional ElGamal if Hybrid.
        Returns (c1, c2, c3, c4) for Hybrid. If RSA-only, c3=c4=None.
        """
        self._log("\n=== ENCRYPTION PHASE ===")
        m = mpz(message)
        self._log(f"  Plaintext m = {m}")

        # RSA portion
        c1 = powmod(m, self.collaborative_key, self.global_modulus)
        c2 = powmod(m, self.source.phi, self.global_modulus)
        self._log(f"  [RSA] c1 = {c1}, c2 = {c2}")

        if self.mode == "Hybrid":
            # ElGamal portion
            e = mpz(random.randint(2, max(3, self.p_g - 2)))
            c3 = powmod(self.g, e, self.p_g)
            Y_e = powmod(self.elgamal_public, e, self.p_g)
            c4 = (m % self.p_g) * Y_e % self.p_g
            self._log(f"  [ElGamal] e={e}, c3={c3}, c4={c4}")
        else:
            c3, c4 = None, None
            self._log("  [RSA Only] No ElGamal ciphertext")

        return (c1, c2, c3, c4)

    def decrypt_message(self, ciphertext):
        """
        Perform FILO RSA, then if Hybrid, ElGamal FILO.
        Returns (rsa_plain, elgamal_plain or None).
        """
        self._log("\n=== DECRYPTION PHASE ===")
        (c1, c2, c3, c4) = ciphertext

        # ----- RSA FILO -----
        self._log("  [RSA FILO Decryption]")
        temp_rsa = c1
        c2_rsa = c2
        # Intermediates in reverse
        for node in reversed(self.intermediates):
            alpha = powmod(c2_rsa, node.r, self.global_modulus)
            inv_alpha = invert(alpha, self.global_modulus)
            temp_rsa = (temp_rsa * inv_alpha) % self.global_modulus
            c2_rsa = powmod(c2_rsa, node.phi, self.global_modulus)
        # Destination
        alpha_dest = powmod(c2_rsa, self.destination.r, self.global_modulus)
        inv_alpha_dest = invert(alpha_dest, self.global_modulus)
        rsa_plain = (temp_rsa * inv_alpha_dest) % self.global_modulus
        self._log(f"    => RSA plaintext: {rsa_plain}")

        elgamal_plain = None
        if self.mode == "Hybrid" and c3 is not None and c4 is not None:
            self._log("\n  [ElGamal FILO Decryption]")
            temp_eg = c4
            # Source -> Intermediates(reverse) -> Destination
            chain = [self.source] + self.intermediates[::-1] + [self.destination]
            for node in chain:
                c3pow = powmod(c3, node.x, self.p_g)
                inv_c3pow = invert(c3pow, self.p_g)
                temp_eg = (temp_eg * inv_c3pow) % self.p_g
            elgamal_plain = temp_eg
            self._log(f"    => ElGamal plaintext: {elgamal_plain}")
        else:
            self._log("\n  [RSA Only] No ElGamal decryption done.")

        return rsa_plain, elgamal_plain


# ------------------------------------------------------------------
# 2) TKINTER GUI THAT INTEGRATES THE SYSTEM ABOVE
# ------------------------------------------------------------------

class IoTCryptoSimulator:
    """Tkinter-based GUI for the IoT Collaborative Encryption."""

    def __init__(self, root):
        self.root = root
        self.root.title("IoT Security Gateway - Collaborative Encryption")
        self.setup_theme()
        self.create_widgets()
        self.running = False

        # We'll store references to the encryption system and last ciphertext
        self.system = None
        self.ciphertext = None
        self.message_input = None

    def setup_theme(self):
        style = ttk.Style()
        style.theme_create('iot', settings={
            "TLabel": {
                "configure": {
                    "background": "#1a1a1a",
                    "foreground": "#00ff00"
                }
            },
            "TButton": {
                "configure": {
                    "background": "#004400",
                    "foreground": "white"
                },
                "map": {
                    "background": [("active", "#006600")]
                }
            },
            "TFrame": {
                "configure": {"background": "#1a1a1a"}
            },
            "TEntry": {
                "configure": {"fieldbackground": "#333333", "foreground": "white"}
            },
            "TCombobox": {
                "configure": {"fieldbackground": "#333333", "foreground": "white"}
            }
        })
        style.theme_use('iot')
        self.root.configure(bg='#1a1a1a')

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ============ INPUT PANEL ============
        input_frame = ttk.LabelFrame(main_frame, text=" Network Configuration ", padding=15)
        input_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ttk.Label(input_frame, text="IoT Nodes:").grid(row=0, column=0, sticky="w")
        self.node_count = ttk.Combobox(input_frame, values=[1,2,3,4,5,6], width=5)
        self.node_count.grid(row=0, column=1, sticky="w")
        self.node_count.set(2)

        ttk.Label(input_frame, text="Key Size (bits):").grid(row=1, column=0, sticky="w")
        self.key_size = ttk.Combobox(input_frame, values=["64", "128", "256"], width=5)
        self.key_size.grid(row=1, column=1, sticky="w")
        self.key_size.set("128")

        ttk.Label(input_frame, text="Security Mode:").grid(row=2, column=0, sticky="w")
        self.security_mode = ttk.Combobox(input_frame,
                                          values=["RSA Only", "Hybrid"],
                                          width=10)
        self.security_mode.grid(row=2, column=1, sticky="w")
        self.security_mode.set("Hybrid")

        ttk.Label(input_frame, text="Message:").grid(row=3, column=0, sticky="w")
        self.msg_var = tk.StringVar(value="123456789")
        msg_entry = ttk.Entry(input_frame, textvariable=self.msg_var, width=20)
        msg_entry.grid(row=3, column=1, sticky="w")

        ttk.Button(input_frame, text="Initialize Network",
                   command=self.start_simulation).grid(row=4, column=0, columnspan=2, pady=10)

        # ============ NETWORK VISUALIZATION ============
        vis_frame = ttk.LabelFrame(main_frame, text=" Device Network ", padding=15)
        vis_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        self.canvas = tk.Canvas(vis_frame, bg="#000000", width=400, height=200)
        self.canvas.pack()
        self.node_leds = []
        self.connection_lines = []

        # ============ STATUS PANEL ============
        status_frame = ttk.LabelFrame(main_frame, text=" Security Operations ", padding=15)
        status_frame.grid(row=0, column=2, sticky="nsew", padx=10, pady=10)

        self.progress = ttk.Progressbar(status_frame, mode='determinate')
        self.progress.pack(fill=tk.X)

        self.console = scrolledtext.ScrolledText(status_frame, bg="#000000",
                                                 fg="#00ff00", width=40, height=10)
        self.console.pack(pady=10)

        ttk.Button(status_frame, text="Terminate Session",
                   command=self.terminate).pack(side=tk.BOTTOM)

        # Configure grid weighting
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=2)
        main_frame.columnconfigure(2, weight=1)
        main_frame.rowconfigure(0, weight=1)

    def draw_network(self):
        """Draw circles for each node: 1 source + N intermediates + 1 destination."""
        self.canvas.delete("all")
        nodes = int(self.node_count.get())
        # We'll show total of nodes+2 (Source and Destination)
        total_nodes = nodes + 2
        node_positions = []
        self.node_leds = []

        for i in range(total_nodes):
            x = 50 + (i * 300 / (total_nodes - 1))
            y = 100
            color = "#ff0000"  # Red = "off"
            tag = "Source" if i == 0 else ("Destination" if i == total_nodes-1 else f"Node {i}")
            # Draw circle
            self.canvas.create_oval(x-15, y-15, x+15, y+15, fill=color, tags=tag)
            self.canvas.create_text(x, y+25, text=tag, fill="white")
            node_positions.append((x, y))
            self.node_leds.append((tag, x, y, color))

        # Draw dashed lines between them
        self.connection_lines.clear()
        for i in range(total_nodes - 1):
            x1, y1 = node_positions[i]
            x2, y2 = node_positions[i+1]
            line = self.canvas.create_line(x1+15, y1, x2-15, y2,
                                           fill="#404040", width=2, dash=(4,2))
            self.connection_lines.append(line)

    def update_led(self, node_index, color):
        """
        node_index=0 => 'Source'
        node_index=last => 'Destination'
        """
        tag, x, y, _ = self.node_leds[node_index]
        self.canvas.itemconfig(tag, fill=color)
        self.canvas.update()

    def log(self, msg, color=None):
        """Write message to scrolled text area."""
        self.console.configure(state='normal')
        self.console.insert(tk.END, msg + "\n")
        self.console.configure(state='disabled')
        self.console.see(tk.END)

    def terminate(self):
        """End session, reset display."""
        self.log("Session terminated.", "#ff0000")
        self.progress["value"] = 0
        self.draw_network()

    def start_simulation(self):
        """Triggered by 'Initialize Network' button. Launch in thread."""
        if self.running:
            return
        self.running = True
        self.draw_network()
        Thread(target=self.run_crypto_operations).start()

    def run_crypto_operations(self):
        try:
            self.log("=== Initializing IoT Network ===")
            self.progress["value"] = 10
            self.update_led(0, "#00ff00")  # source is "on"

            # Convert user inputs
            nodes = int(self.node_count.get())
            bits = int(self.key_size.get())
            mode = "RSA" if self.security_mode.get() == "RSA Only" else "Hybrid"
            msg_text = self.msg_var.get()
            try:
                message_val = int(msg_text)
            except ValueError:
                self.log("ERROR: Message must be an integer. Using 12345.")
                message_val = 12345

            # We'll color intermediate nodes in yellow while "initializing"
            total_nodes = nodes + 2
            for i in range(1, total_nodes-1):
                self.update_led(i, "#ffff00")  # "in progress"
                self.log(f"Node {i} powering up...")
                self.root.update()
                self.root.after(200)

            self.update_led(total_nodes-1, "#00ff00")  # Destination on
            self.progress["value"] = 30

            # Build the real encryption system
            self.log("\n+++ Building Collaborative Encryption System +++")
            self.system = CollaborativeEncryptionSystem(
                num_intermediates=nodes,
                prime_bits=bits,
                mode=mode,
                logger=self.log
            )
            self.progress["value"] = 50
            self.log("\n+++ Encrypting Message +++")

            # Perform encryption
            self.ciphertext = self.system.encrypt_message(message_val)
            self.log(f"Ciphertext: {self.ciphertext}")

            # Light up lines
            for line in self.connection_lines:
                self.canvas.itemconfig(line, fill="#00ff00")
                self.root.update()
                self.root.after(150)
            self.progress["value"] = 70

            self.log("\n+++ Decrypting Message +++")
            rsa_plain, elgamal_plain = self.system.decrypt_message(self.ciphertext)
            self.log(f"\nDecryption => RSA: {rsa_plain}, ElGamal: {elgamal_plain if elgamal_plain is not None else 'N/A'}")

            if mode == "Hybrid":
                if rsa_plain == elgamal_plain == message_val:
                    self.log("\nSUCCESS: Both RSA & ElGamal match original message!")
                else:
                    self.log("\nFAILURE: RSA or ElGamal mismatch the original message!")
            else:
                # RSA only: only rsa_plain is relevant
                if rsa_plain == message_val:
                    self.log("\nSUCCESS: RSA Plaintext matches original message!")
                else:
                    self.log("\nFAILURE: RSA Plaintext mismatch!")
            self.progress["value"] = 100

            self.log("\n=== Network Secured ===")
        except Exception as e:
            self.log(f"Error: {str(e)}", "#ff0000")
        finally:
            self.running = False


# ------------------------------------------------------------------
# 3) MAIN ENTRY POINT
# ------------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1200x600")
    app = IoTCryptoSimulator(root)
    root.mainloop()
